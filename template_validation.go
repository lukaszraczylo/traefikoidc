package traefikoidc

import (
	"fmt"
	"strings"
	"text/template/parse"
)

// allowedRootTokenFields are the non-Claims values a header template may render
// directly from the root data context. Both ID-token spellings are accepted
// (templateData carries IDToken and IdToken).
var allowedRootTokenFields = map[string]bool{
	"AccessToken":  true,
	"IdToken":      true,
	"IDToken":      true,
	"RefreshToken": true,
}

// validateTemplateParseFuncs is the function set the parser is told about. Only
// get/default exist; every other identifier used as a command (printf, call,
// index, js, ...) then fails to parse and is rejected — no blocklist needed.
var validateTemplateParseFuncs = map[string]any{
	"get":     struct{}{},
	"default": struct{}{},
}

// claimsWhitelist returns the effective set of claim field names a header
// template may emit: the built-in safeClaimsFields plus any operator-configured
// extras (config.AllowedClaims). Blank/whitespace extras are ignored. The result
// gates BOTH static validation and the runtime get helper so the two never drift.
func claimsWhitelist(extra []string) map[string]bool {
	m := make(map[string]bool, len(safeClaimsFields)+len(extra))
	for k := range safeClaimsFields {
		m[k] = true
	}
	for _, c := range extra {
		if c = strings.TrimSpace(c); c != "" {
			m[c] = true
		}
	}
	return m
}

// templateValidator walks a parsed header template against a specific claims
// whitelist (built-in + operator-configured). Holding the set on the walker
// keeps it out of every method signature.
type templateValidator struct {
	allowed map[string]bool
}

// validateTemplateSecure parses a header value template and walks its AST,
// permitting ONLY: literal text; the whitelisted root token fields; whitelisted
// .Claims.<field> access; range/with over a whitelisted .Claims.<field>; the
// safe get/default helpers; and {{if}} control flow. Everything else — bare
// {{.}}/{{$}} (whole-root dump), bare {{.Claims}} (whole-map dump), non-
// whitelisted claims, unknown functions, define/template/block — is rejected.
//
// allowed is the effective claim whitelist (see claimsWhitelist); a nil set
// falls back to the built-in safeClaimsFields.
//
// Parsing (not substring matching) is what makes this sound: the parser resolves
// whitespace, comments and the meaning of "." per scope, so obfuscation and the
// "whitelisted decoy + bare-map render" bypass class cannot slip through.
func validateTemplateSecure(templateStr string, allowed map[string]bool) error {
	if allowed == nil {
		allowed = safeClaimsFields
	}
	trees, err := parse.Parse("headerTemplate", templateStr, "{{", "}}", validateTemplateParseFuncs)
	if err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}
	// {{define}}/{{block}} produce additional named trees; a header value template
	// must be a single anonymous template, so reject anything that defines more.
	if len(trees) != 1 {
		return fmt.Errorf("template definitions ({{define}}/{{block}}) are not allowed")
	}
	tree, ok := trees["headerTemplate"]
	if !ok || tree.Root == nil {
		return fmt.Errorf("invalid template: empty parse tree")
	}
	v := &templateValidator{allowed: allowed}
	// dotIsRoot=true: "." is the whole data context at the top level. Inside a
	// range/with over a claims field it rebinds to that (already-whitelisted)
	// element, so relative access there is safe.
	return v.walkNode(tree.Root, true)
}

// walkNode validates a node and its children. dotIsRoot reports whether "."
// currently refers to the root data context (true) or to a whitelisted claim
// element rebound by an enclosing range/with (false).
func (v *templateValidator) walkNode(n parse.Node, dotIsRoot bool) error {
	switch node := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if node == nil {
			return nil
		}
		for _, child := range node.Nodes {
			if err := v.walkNode(child, dotIsRoot); err != nil {
				return err
			}
		}
		return nil
	case *parse.TextNode:
		return nil
	case *parse.ActionNode:
		return v.validatePipe(node.Pipe, dotIsRoot)
	case *parse.IfNode:
		return v.walkBranch(node.Pipe, node.List, node.ElseList, dotIsRoot, dotIsRoot)
	case *parse.WithNode:
		// with rebinds "." to the target inside its body; the target must be a
		// whitelisted claim, so the body runs with dotIsRoot=false.
		if err := v.validateClaimSelector(node.Pipe, dotIsRoot, "with"); err != nil {
			return err
		}
		return v.walkBranch(nil, node.List, node.ElseList, false, dotIsRoot)
	case *parse.RangeNode:
		// range iterates the target and rebinds "." to each element; the target
		// must be a whitelisted claim collection, so the body is dotIsRoot=false.
		if err := v.validateClaimSelector(node.Pipe, dotIsRoot, "range"); err != nil {
			return err
		}
		return v.walkBranch(nil, node.List, node.ElseList, false, dotIsRoot)
	case *parse.TemplateNode:
		return fmt.Errorf("template inclusion is not allowed")
	default:
		return fmt.Errorf("unsupported template construct: %s", n.String())
	}
}

// walkBranch validates an if/with/range: an optional condition pipe (evaluated
// in the outer scope), the body (bodyDotIsRoot), and the else branch (outer
// scope). For with/range the condition pipe is validated by the caller and
// condPipe is nil here.
func (v *templateValidator) walkBranch(condPipe *parse.PipeNode, body, elseList *parse.ListNode, bodyDotIsRoot, outerDotIsRoot bool) error {
	if condPipe != nil {
		if err := v.validatePipe(condPipe, outerDotIsRoot); err != nil {
			return err
		}
	}
	if err := v.walkNode(body, bodyDotIsRoot); err != nil {
		return err
	}
	if elseList != nil {
		if err := v.walkNode(elseList, outerDotIsRoot); err != nil {
			return err
		}
	}
	return nil
}

// validatePipe validates every command in a pipeline, including the right-hand
// side of any variable declaration ($x := ...). Declared vars therefore always
// hold already-validated values, so later references to them are safe.
func (v *templateValidator) validatePipe(pipe *parse.PipeNode, dotIsRoot bool) error {
	if pipe == nil {
		return nil
	}
	for _, cmd := range pipe.Cmds {
		if err := v.validateCommand(cmd, dotIsRoot); err != nil {
			return err
		}
	}
	return nil
}

// validateCommand validates a single command (one stage of a pipeline). The
// first argument may be the get/default function; the rest, and every argument
// of a non-function command, must be a safe value expression.
func (v *templateValidator) validateCommand(cmd *parse.CommandNode, dotIsRoot bool) error {
	if cmd == nil || len(cmd.Args) == 0 {
		return nil
	}
	if id, ok := cmd.Args[0].(*parse.IdentifierNode); ok {
		return v.validateFunctionCall(id.Ident, cmd.Args[1:], dotIsRoot)
	}
	for _, arg := range cmd.Args {
		if err := v.validateValue(arg, dotIsRoot); err != nil {
			return err
		}
	}
	return nil
}

// validateFunctionCall allows only get/default. get's map argument must be a
// claims reference (never the root) and default's arguments are validated as
// values; the runtime get additionally enforces the key whitelist.
func (v *templateValidator) validateFunctionCall(name string, args []parse.Node, dotIsRoot bool) error {
	switch name {
	case "default":
		for _, arg := range args {
			if err := v.validateValue(arg, dotIsRoot); err != nil {
				return err
			}
		}
		return nil
	case "get":
		if len(args) < 1 {
			return fmt.Errorf("get requires a map argument")
		}
		// The map argument must reference .Claims, never the root map (which
		// would expose tokens / the whole Claims map). Remaining args (the key,
		// possibly a pipeline) are validated as values.
		if err := v.validateClaimsReference(args[0], dotIsRoot); err != nil {
			return fmt.Errorf("get is only allowed on .Claims: %w", err)
		}
		// A literal key must be whitelisted (matches direct .Claims.<field>
		// strictness); a dynamic key is enforced by the runtime get.
		if len(args) >= 2 {
			if key, ok := args[1].(*parse.StringNode); ok && !v.allowed[key.Text] {
				return fmt.Errorf("access to Claims.%s is not allowed for security reasons", key.Text)
			}
		}
		for _, arg := range args[1:] {
			if err := v.validateValue(arg, dotIsRoot); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("function %q is not allowed in header templates", name)
	}
}

// validateValue validates an expression that may be rendered or passed as an
// argument. It rejects anything resolving to the whole root or the whole Claims
// map, and any non-whitelisted claim.
func (v *templateValidator) validateValue(node parse.Node, dotIsRoot bool) error {
	switch val := node.(type) {
	case *parse.StringNode, *parse.NumberNode, *parse.BoolNode, *parse.NilNode:
		return nil
	case *parse.DotNode:
		// "." is the whole root at the top level (dumps tokens + all claims); it
		// is a single already-whitelisted claim element inside a range/with body.
		if dotIsRoot {
			return fmt.Errorf("rendering the whole data context ({{.}}) is not allowed")
		}
		return nil
	case *parse.FieldNode:
		return v.validateFieldAccess(val.Ident, dotIsRoot)
	case *parse.VariableNode:
		return v.validateVariableAccess(val.Ident)
	case *parse.PipeNode:
		return v.validatePipe(val, dotIsRoot)
	case *parse.ChainNode:
		// (base).Field.Field — the field chain only narrows access, so validating
		// the base value is sufficient.
		return v.validateValue(val.Node, dotIsRoot)
	default:
		return fmt.Errorf("unsupported template expression: %s", node.String())
	}
}

// validateFieldAccess validates a dot-relative field access ".A.B.C" given
// whether "." is the root. In an element scope (dotIsRoot=false) the element is
// already a whitelisted claim, so any sub-field access is safe.
func (v *templateValidator) validateFieldAccess(idents []string, dotIsRoot bool) error {
	if !dotIsRoot {
		return nil
	}
	if len(idents) == 0 {
		return fmt.Errorf("rendering the whole data context is not allowed")
	}
	root := idents[0]
	if allowedRootTokenFields[root] {
		return nil
	}
	if root == "Claims" {
		if len(idents) < 2 {
			return fmt.Errorf("rendering the whole Claims map ({{.Claims}}) is not allowed")
		}
		if !v.allowed[idents[1]] {
			return fmt.Errorf("access to Claims.%s is not allowed for security reasons", idents[1])
		}
		// By design, only the top-level claim is whitelisted; deeper subfields
		// (idents[2:]) of a map-valued whitelisted claim such as realm_access /
		// resource_access are forwarded as-is. Whitelisting a map claim means
		// opting into its nested contents, and the documented Keycloak pattern
		// {{with .Claims.realm_access}}{{.roles}}{{end}} relies on it; nested
		// provider keys can't be enumerated to whitelist individually.
		return nil
	}
	return fmt.Errorf("access to .%s is not allowed in header templates", root)
}

// validateVariableAccess validates a $-variable reference. The bare root ("$"
// and "$.x") is treated as a root field access; a named range/with/declaration
// variable holds an already-validated value, so it and its sub-fields are safe.
func (v *templateValidator) validateVariableAccess(idents []string) error {
	if len(idents) == 0 {
		return nil
	}
	if idents[0] == "$" {
		// "$" is the root: "$" alone dumps everything; "$.Claims.email" is a
		// root-absolute field access validated like ".Claims.email".
		if len(idents) == 1 {
			return fmt.Errorf("rendering the whole data context ({{$}}) is not allowed")
		}
		return v.validateFieldAccess(idents[1:], true)
	}
	// Named variable ($e, $i, $x): holds a validated element/index/value.
	return nil
}

// validateClaimsReference requires a node to reference .Claims (or $.Claims),
// never the root map — used for get's map argument, whose key is separately
// enforced against the whitelist at render time.
func (v *templateValidator) validateClaimsReference(node parse.Node, dotIsRoot bool) error {
	switch ref := node.(type) {
	case *parse.FieldNode:
		if dotIsRoot && len(ref.Ident) >= 1 && ref.Ident[0] == "Claims" {
			if len(ref.Ident) >= 2 && !v.allowed[ref.Ident[1]] {
				return fmt.Errorf("access to Claims.%s is not allowed for security reasons", ref.Ident[1])
			}
			return nil
		}
	case *parse.VariableNode:
		if len(ref.Ident) >= 2 && ref.Ident[0] == "$" && ref.Ident[1] == "Claims" {
			if len(ref.Ident) >= 3 && !v.allowed[ref.Ident[2]] {
				return fmt.Errorf("access to Claims.%s is not allowed for security reasons", ref.Ident[2])
			}
			return nil
		}
	}
	return fmt.Errorf("expected a .Claims reference")
}

// validateClaimSelector validates the target of a range/with: it must iterate a
// specific whitelisted claim field (.Claims.<field> or $.Claims.<field>), never
// the bare Claims map or any non-claims value.
func (v *templateValidator) validateClaimSelector(pipe *parse.PipeNode, dotIsRoot bool, kind string) error {
	if pipe == nil || len(pipe.Cmds) == 0 {
		return fmt.Errorf("%s requires a .Claims.<field> target", kind)
	}
	cmd := pipe.Cmds[len(pipe.Cmds)-1]
	if len(cmd.Args) == 0 {
		return fmt.Errorf("%s requires a .Claims.<field> target", kind)
	}
	target := cmd.Args[0]
	if err := v.validateClaimField(target, dotIsRoot); err != nil {
		return fmt.Errorf("%s is only allowed over a whitelisted claims field, e.g. {{range $i, $e := .Claims.groups}} or {{with .Claims.email}}: %w", kind, err)
	}
	return nil
}

// validateClaimField requires a node to be a specific whitelisted claim field
// (.Claims.<whitelisted> or $.Claims.<whitelisted>) — stricter than
// validateClaimsReference, which also permits the bare .Claims map for get.
func (v *templateValidator) validateClaimField(node parse.Node, dotIsRoot bool) error {
	switch field := node.(type) {
	case *parse.FieldNode:
		if dotIsRoot && len(field.Ident) >= 2 && field.Ident[0] == "Claims" && v.allowed[field.Ident[1]] {
			return nil
		}
	case *parse.VariableNode:
		if len(field.Ident) >= 3 && field.Ident[0] == "$" && field.Ident[1] == "Claims" && v.allowed[field.Ident[2]] {
			return nil
		}
	}
	return fmt.Errorf("not a whitelisted .Claims.<field>")
}
