package revip

import (
	"fmt"
	"reflect"
	"strings"
	"sort"
)

type (
	Tree interface {
		Interface() interface{}
		Value() reflect.Value
		WithValue(reflect.Value) Tree
		Next() []Tree
		WithNext(Tree) Tree
		Previous() Tree
		WithPrevious(Tree) Tree
		Name() string
	}
	TreeNode struct {
		Val    reflect.Value
		Childs []Tree
		Parent Tree
	}
	TreeStructFieldNode struct {
		Tree
		Field reflect.StructField
	}
	TreeMapFieldNode struct {
		Tree
		Field reflect.Value
	}
	TreeSliceFieldNode struct {
		Tree
		Field int
	}
	TreeArrayFieldNode struct {
		Tree
		Field int
	}
)

var (
	_ Tree = new(TreeNode)
	_ Tree = new(TreeStructFieldNode)
	_ Tree = new(TreeMapFieldNode)
	_ Tree = new(TreeSliceFieldNode)
	_ Tree = new(TreeArrayFieldNode)
)

func (n *TreeNode) Interface() interface{} { return n.Val.Interface() }
func (n *TreeNode) Value() reflect.Value   { return n.Val }
func (n *TreeNode) WithValue(v reflect.Value) Tree {
	n.Val = v
	return n
}

func (n *TreeNode) Next() []Tree { return n.Childs }
func (n *TreeNode) WithNext(t Tree) Tree {
	n.Childs = append(n.Childs, t)
	return n
}

func (n *TreeNode) Previous() Tree { return n.Parent }
func (n *TreeNode) WithPrevious(t Tree) Tree {
	n.Parent = t
	return n
}

func (n *TreeNode) Name() string {
	t := strings.Split(fmt.Sprintf("%T", n.Val.Interface()), ".")
	return "." + t[len(t)-1]
}
func (n *TreeStructFieldNode) Name() string { return "." + n.Field.Name }
func (n *TreeMapFieldNode) Name() string    { return fmt.Sprintf("[%v]", n.Field.Interface()) }
func (n *TreeSliceFieldNode) Name() string  { return fmt.Sprintf("[%d]", n.Field) }
func (n *TreeArrayFieldNode) Name() string  { return fmt.Sprintf("[%d]", n.Field) }

func TreePathSlice(t Tree) []Tree {
	var (
		curr Tree = t
		path []Tree
	)
	for {
		if curr == nil {
			break
		}
		path = append(path, curr)
		curr = curr.Previous()
	}

	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	return path
}

func TreePathString(t Tree) string {
	s := ""
	for _, node := range TreePathSlice(t) {
		s += node.Name()
	}
	return s
}

//

func newTree(previous Tree, node Tree, value reflect.Value, handler func(Tree) error) error {
	var err error

	node.WithValue(value)
	if previous != nil {
		node.WithPrevious(previous)
		previous.WithNext(node)
	}

	if handler != nil {
		err = handler(node)
		if err != nil {
			return err
		}
	}

	switch value.Kind() {
	case reflect.Struct:
		t := value.Type()
		for n := 0; n < value.NumField(); n++ {
			f := t.Field(n)
			if !f.IsExported() {
				continue
			}
			err = newTree(
				node,
				&TreeStructFieldNode{Field: f, Tree: &TreeNode{}},
				value.Field(n),
				handler,
			)
			if err != nil {
				return err
			}
		}
	case reflect.Map:
		keys := value.MapKeys()
		m := map[string]*TreeMapFieldNode{}
		mk := make([]string, len(keys))
		for n, k := range keys {
			key := fmt.Sprintf("%v", k.Interface())
			m[key] = &TreeMapFieldNode{Field: k, Tree: &TreeNode{}}
			mk[n] = key
		}

		sort.Strings(mk)

		for _, key := range mk {
			err = newTree(
				node,
				m[key],
				value.MapIndex(m[key].Field),
				handler,
			)
			if err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for n := 0; n < value.Len(); n++ {
			err = newTree(
				node,
				&TreeSliceFieldNode{Field: n, Tree: &TreeNode{}},
				value.Index(n),
				handler,
			)
			if err != nil {
				return err
			}
		}
	case reflect.Ptr:
		if !value.IsNil() {
			err = newTree(node, &TreeNode{}, value.Elem(), handler)
			if err != nil {
				return err
			}
		}
	case reflect.String:
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	case reflect.Bool:
	case reflect.Float32, reflect.Float64:
	case reflect.Complex64, reflect.Complex128:
	case reflect.Chan:
	case reflect.Func:
	case reflect.Interface:
	case reflect.Uintptr:
	default:
		panic(fmt.Errorf("unsupported kind %q", value.Kind()))
	}
	return nil
}

func NewTree(value reflect.Value, handler func(Tree) error) (Tree, error) {
	var (
		root = &TreeNode{}
		err  = newTree(nil, root, value, handler)
	)
	if err != nil {
		return nil, err
	}
	return root, nil
}
