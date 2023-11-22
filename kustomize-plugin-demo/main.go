package main

import (
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/command"
	"sigs.k8s.io/kustomize/kyaml/kio"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

type ValueAnnotator struct {
	BundleRoot string `yaml:"bundleRoot" json:"bundleRoot"`
	InstallNamespace string `yaml:"installnamespace" json:"installnamespace"`
	PackageName string `yaml:"packageName" json:"packageName"`
	TargetNamespaces []string `yaml:"targetNamespaces" json:"targetNamespaces"`
}

const maxNameLength = 63

func main() {
	config := new(ValueAnnotator)
	fn := func(items []*yaml.RNode) ([]*yaml.RNode, error) {
		if len(items) > 1 {
			return nil, errors.New("more than one manifest has been provided. Check your templating logic.")
		}

		resource := items[0]

		if resource.GetKind() != v1alpha1.ClusterServiceVersionKind {
			return nil, fmt.Errorf("object sent to the plugin is not CSV: %v", resource.GetName())
		}

		var (
			installNamespace string
			targetNamespaces []string
		)

		installNamespace = config.InstallNamespace
		if installNamespace == "" {
			installNamespace = resource.GetAnnotations()["operatorframework.io/suggested-namespace"]
		}

		if installNamespace == "" {
			installNamespace = fmt.Sprintf("%s-system", config.PackageName) 
		}

		csv, err := getCSV(resource)
		if err != nil {
			return nil, fmt.Errorf("trying to fetch csv: %v", err)
		}

		supportedInstallModes := sets.New[string]()
		for _, im := range csv.Spec.InstallModes {
			if im.Supported {
				supportedInstallModes.Insert(string(im.Type))
			}
		}
		if !supportedInstallModes.Has(string(v1alpha1.InstallModeTypeAllNamespaces)) {
			return nil, errors.New("AllNamespace install mode must be enabled")
		}

		targetNamespaces = config.TargetNamespaces
		if targetNamespaces == nil {
			if supportedInstallModes.Has(string(v1alpha1.InstallModeTypeAllNamespaces)) {
				targetNamespaces = []string{""}
			} else if supportedInstallModes.Has(string(v1alpha1.InstallModeTypeOwnNamespace)) {
				targetNamespaces = []string{installNamespace}
			}
		}

		if err := validateTargetNamespaces(supportedInstallModes, installNamespace, targetNamespaces); err != nil {
			return nil, err
		}

		if len(csv.Spec.APIServiceDefinitions.Owned) > 0 {
			return nil, fmt.Errorf("apiServiceDefintions are not supported")
		}
	
		if len(csv.Spec.WebhookDefinitions) > 0 {
			return nil, fmt.Errorf("webhookDefinitions are not supported")
		}

		deployments := []appsv1.Deployment{}
		serviceAccounts := map[string]corev1.ServiceAccount{}
		for _, depSpec := range csv.Spec.InstallStrategy.StrategySpec.DeploymentSpecs {
			annotations := mergeMaps(csv.Annotations, depSpec.Spec.Template.Annotations)
			annotations["olm.targetNamespaces"] = strings.Join(targetNamespaces, ",")
			deployments = append(deployments, appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: appsv1.SchemeGroupVersion.String(),
				},

				ObjectMeta: metav1.ObjectMeta{
					Namespace:   installNamespace,
					Name:        depSpec.Name,
					Labels:      depSpec.Label,
					Annotations: annotations,
				},
				Spec: depSpec.Spec,
			})
			saName := saNameOrDefault(depSpec.Spec.Template.Spec.ServiceAccountName)
			serviceAccounts[saName] = newServiceAccount(installNamespace, saName)
		}

		roles := []rbacv1.Role{}
		roleBindings := []rbacv1.RoleBinding{}
		clusterRoles := []rbacv1.ClusterRole{}
		clusterRoleBindings := []rbacv1.ClusterRoleBinding{}

		permissions := csv.Spec.InstallStrategy.StrategySpec.Permissions
		clusterPermissions := csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions
		allPermissions := append(permissions, clusterPermissions...)

		// Create all the service accounts
		for _, permission := range allPermissions {
			saName := saNameOrDefault(permission.ServiceAccountName)
			if _, ok := serviceAccounts[saName]; !ok {
				serviceAccounts[saName] = newServiceAccount(installNamespace, saName)
			}
		}

		// If we're in AllNamespaces mode, promote the permissions to clusterPermissions
		if len(targetNamespaces) == 1 && targetNamespaces[0] == "" {
			for _, p := range permissions {
				p.Rules = append(p.Rules, rbacv1.PolicyRule{
					Verbs:     []string{"get", "list", "watch"},
					APIGroups: []string{corev1.GroupName},
					Resources: []string{"namespaces"},
				})
			}
			clusterPermissions = append(clusterPermissions, permissions...)
			permissions = nil
		}

		for _, permission := range permissions {
			saName := saNameOrDefault(permission.ServiceAccountName)
			name := generateName(fmt.Sprintf("%s-%s", csv.Name, saName), []interface{}{csv.Name, permission})
			roles = append(roles, newRole(installNamespace, name, permission.Rules))
			roleBindings = append(roleBindings, newRoleBinding(installNamespace, name, name, installNamespace, saName))
		}
		for _, permission := range clusterPermissions {
			saName := saNameOrDefault(permission.ServiceAccountName)
			name := generateName(fmt.Sprintf("%s-%s", csv.Name, saName), []interface{}{csv.GetName(), permission})
			clusterRoles = append(clusterRoles, newClusterRole(name, permission.Rules))
			clusterRoleBindings = append(clusterRoleBindings, newClusterRoleBinding(name, name, installNamespace, saName))
		}

		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: installNamespace},
		}

		objs := []client.Object{ns}
		for _, obj := range serviceAccounts {
			obj := obj
			if obj.GetName() != "default" {
				objs = append(objs, &obj)
			}
		}
		for _, obj := range roles {
			obj := obj
			objs = append(objs, &obj)
		}
		for _, obj := range roleBindings {
			obj := obj
			objs = append(objs, &obj)
		}
		for _, obj := range clusterRoles {
			obj := obj
			objs = append(objs, &obj)
		}
		for _, obj := range clusterRoleBindings {
			obj := obj
			objs = append(objs, &obj)
		}
		for _, obj := range deployments {
			obj := obj
			objs = append(objs, &obj)
		}
		return  convertObjToNode(objs)
	}
	p := framework.SimpleProcessor{Config: config, Filter: kio.FilterFunc(fn)}
	cmd := command.Build(p, command.StandaloneDisabled, false)
	command.AddGenerateDockerfile(cmd)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func convertObjToNode(objects []client.Object) ([]*yaml.RNode, error) {
	var result []*yaml.RNode
	for _, obj := range objects {
		// Convert Unstructured to RNode
		node, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&obj)
		if err != nil {
			return nil, fmt.Errorf("Error converting to Unstructured: %v\n", err)
		}
		yamlBytes, err := yaml.Marshal(node)
		if err != nil {
			return nil, fmt.Errorf("Error converting to RNode: %v\n", err)	
		}

		r, err := yaml.Parse(string(yamlBytes)) 
		if err != nil {
			return nil, fmt.Errorf("Error parsing to RNode: %v\n", err)	
		}

		result = append(result, r)
	}

	return result, nil
}


func getCSV(rNode *yaml.RNode) (*v1alpha1.ClusterServiceVersion, error) {
	// Convert RNode to Unstructured
	unstructredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(rNode)
	if err != nil {
		return nil, fmt.Errorf("while converting to unstructured %v", err)
	}

	var csv v1alpha1.ClusterServiceVersion
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructredObj, &csv)
	if err != nil {
		return nil, fmt.Errorf("while converting to structured obj %v", err)
	}

	return &csv, nil
}

func saNameOrDefault(saName string) string {
	if saName == "" {
		return "default"
	}
	return saName
}

func newRole(namespace, name string, rules []rbacv1.PolicyRule) rbacv1.Role {
	return rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Rules: rules,
	}
}

func newServiceAccount(namespace, name string) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
}

func mergeMaps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func generateName(base string, o interface{}) string {
	hasher := fnv.New32a()

	DeepHashObject(hasher, o)
	hashStr := rand.SafeEncodeString(fmt.Sprint(hasher.Sum32()))
	if len(base)+len(hashStr) > maxNameLength {
		base = base[:maxNameLength-len(hashStr)-1]
	}

	return fmt.Sprintf("%s-%s", base, hashStr)
}

func validateTargetNamespaces(supportedInstallModes sets.Set[string], installNamespace string, targetNamespaces []string) error {
	set := sets.New[string](targetNamespaces...)
	switch set.Len() {
	case 0:
		if supportedInstallModes.Has(string(v1alpha1.InstallModeTypeAllNamespaces)) {
			return nil
		}
	case 1:
		if set.Has("") && supportedInstallModes.Has(string(v1alpha1.InstallModeTypeAllNamespaces)) {
			return nil
		}
		if supportedInstallModes.Has(string(v1alpha1.InstallModeTypeSingleNamespace)) {
			return nil
		}
		if supportedInstallModes.Has(string(v1alpha1.InstallModeTypeOwnNamespace)) && targetNamespaces[0] == installNamespace {
			return nil
		}
	default:
		if supportedInstallModes.Has(string(v1alpha1.InstallModeTypeMultiNamespace)) {
			return nil
		}
	}
	return fmt.Errorf("supported install modes %v do not support target namespaces %v", sets.List[string](supportedInstallModes), targetNamespaces)
}

func newClusterRole(name string, rules []rbacv1.PolicyRule) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Rules: rules,
	}
}

func newRoleBinding(namespace, name, roleName, saNamespace string, saNames ...string) rbacv1.RoleBinding {
	subjects := make([]rbacv1.Subject, 0, len(saNames))
	for _, saName := range saNames {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Namespace: saNamespace,
			Name:      saName,
		})
	}
	return rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Subjects: subjects,
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     roleName,
		},
	}
}


// DeepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
// From https://github.com/operator-framework/operator-lifecycle-manager/blob/master/pkg/lib/kubernetes/pkg/util/hash/hash.go
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}


func newClusterRoleBinding(name, roleName, saNamespace string, saNames ...string) rbacv1.ClusterRoleBinding {
	subjects := make([]rbacv1.Subject, 0, len(saNames))
	for _, saName := range saNames {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Namespace: saNamespace,
			Name:      saName,
		})
	}
	return rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Subjects: subjects,
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     roleName,
		},
	}
}
