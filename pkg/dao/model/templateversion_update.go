// SPDX-FileCopyrightText: 2023 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus". DO NOT EDIT.

package model

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"errors"
	"fmt"
	"reflect"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"

	"github.com/seal-io/walrus/pkg/dao/model/internal"
	"github.com/seal-io/walrus/pkg/dao/model/predicate"
	"github.com/seal-io/walrus/pkg/dao/model/resource"
	"github.com/seal-io/walrus/pkg/dao/model/resourcedefinitionmatchingrule"
	"github.com/seal-io/walrus/pkg/dao/model/templateversion"
	"github.com/seal-io/walrus/pkg/dao/types"
	"github.com/seal-io/walrus/pkg/dao/types/object"
)

// TemplateVersionUpdate is the builder for updating TemplateVersion entities.
type TemplateVersionUpdate struct {
	config
	hooks     []Hook
	mutation  *TemplateVersionMutation
	modifiers []func(*sql.UpdateBuilder)
	object    *TemplateVersion
}

// Where appends a list predicates to the TemplateVersionUpdate builder.
func (tvu *TemplateVersionUpdate) Where(ps ...predicate.TemplateVersion) *TemplateVersionUpdate {
	tvu.mutation.Where(ps...)
	return tvu
}

// SetUpdateTime sets the "update_time" field.
func (tvu *TemplateVersionUpdate) SetUpdateTime(t time.Time) *TemplateVersionUpdate {
	tvu.mutation.SetUpdateTime(t)
	return tvu
}

// SetSchema sets the "schema" field.
func (tvu *TemplateVersionUpdate) SetSchema(tvs types.TemplateVersionSchema) *TemplateVersionUpdate {
	tvu.mutation.SetSchema(tvs)
	return tvu
}

// SetNillableSchema sets the "schema" field if the given value is not nil.
func (tvu *TemplateVersionUpdate) SetNillableSchema(tvs *types.TemplateVersionSchema) *TemplateVersionUpdate {
	if tvs != nil {
		tvu.SetSchema(*tvs)
	}
	return tvu
}

// SetUiSchema sets the "uiSchema" field.
func (tvu *TemplateVersionUpdate) SetUiSchema(ts types.UISchema) *TemplateVersionUpdate {
	tvu.mutation.SetUiSchema(ts)
	return tvu
}

// SetNillableUiSchema sets the "uiSchema" field if the given value is not nil.
func (tvu *TemplateVersionUpdate) SetNillableUiSchema(ts *types.UISchema) *TemplateVersionUpdate {
	if ts != nil {
		tvu.SetUiSchema(*ts)
	}
	return tvu
}

// SetSchemaDefaultValue sets the "schema_default_value" field.
func (tvu *TemplateVersionUpdate) SetSchemaDefaultValue(b []byte) *TemplateVersionUpdate {
	tvu.mutation.SetSchemaDefaultValue(b)
	return tvu
}

// ClearSchemaDefaultValue clears the value of the "schema_default_value" field.
func (tvu *TemplateVersionUpdate) ClearSchemaDefaultValue() *TemplateVersionUpdate {
	tvu.mutation.ClearSchemaDefaultValue()
	return tvu
}

// AddResourceIDs adds the "resources" edge to the Resource entity by IDs.
func (tvu *TemplateVersionUpdate) AddResourceIDs(ids ...object.ID) *TemplateVersionUpdate {
	tvu.mutation.AddResourceIDs(ids...)
	return tvu
}

// AddResources adds the "resources" edges to the Resource entity.
func (tvu *TemplateVersionUpdate) AddResources(r ...*Resource) *TemplateVersionUpdate {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvu.AddResourceIDs(ids...)
}

// AddResourceDefinitionIDs adds the "resource_definitions" edge to the ResourceDefinitionMatchingRule entity by IDs.
func (tvu *TemplateVersionUpdate) AddResourceDefinitionIDs(ids ...object.ID) *TemplateVersionUpdate {
	tvu.mutation.AddResourceDefinitionIDs(ids...)
	return tvu
}

// AddResourceDefinitions adds the "resource_definitions" edges to the ResourceDefinitionMatchingRule entity.
func (tvu *TemplateVersionUpdate) AddResourceDefinitions(r ...*ResourceDefinitionMatchingRule) *TemplateVersionUpdate {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvu.AddResourceDefinitionIDs(ids...)
}

// Mutation returns the TemplateVersionMutation object of the builder.
func (tvu *TemplateVersionUpdate) Mutation() *TemplateVersionMutation {
	return tvu.mutation
}

// ClearResources clears all "resources" edges to the Resource entity.
func (tvu *TemplateVersionUpdate) ClearResources() *TemplateVersionUpdate {
	tvu.mutation.ClearResources()
	return tvu
}

// RemoveResourceIDs removes the "resources" edge to Resource entities by IDs.
func (tvu *TemplateVersionUpdate) RemoveResourceIDs(ids ...object.ID) *TemplateVersionUpdate {
	tvu.mutation.RemoveResourceIDs(ids...)
	return tvu
}

// RemoveResources removes "resources" edges to Resource entities.
func (tvu *TemplateVersionUpdate) RemoveResources(r ...*Resource) *TemplateVersionUpdate {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvu.RemoveResourceIDs(ids...)
}

// ClearResourceDefinitions clears all "resource_definitions" edges to the ResourceDefinitionMatchingRule entity.
func (tvu *TemplateVersionUpdate) ClearResourceDefinitions() *TemplateVersionUpdate {
	tvu.mutation.ClearResourceDefinitions()
	return tvu
}

// RemoveResourceDefinitionIDs removes the "resource_definitions" edge to ResourceDefinitionMatchingRule entities by IDs.
func (tvu *TemplateVersionUpdate) RemoveResourceDefinitionIDs(ids ...object.ID) *TemplateVersionUpdate {
	tvu.mutation.RemoveResourceDefinitionIDs(ids...)
	return tvu
}

// RemoveResourceDefinitions removes "resource_definitions" edges to ResourceDefinitionMatchingRule entities.
func (tvu *TemplateVersionUpdate) RemoveResourceDefinitions(r ...*ResourceDefinitionMatchingRule) *TemplateVersionUpdate {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvu.RemoveResourceDefinitionIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (tvu *TemplateVersionUpdate) Save(ctx context.Context) (int, error) {
	if err := tvu.defaults(); err != nil {
		return 0, err
	}
	return withHooks(ctx, tvu.sqlSave, tvu.mutation, tvu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (tvu *TemplateVersionUpdate) SaveX(ctx context.Context) int {
	affected, err := tvu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (tvu *TemplateVersionUpdate) Exec(ctx context.Context) error {
	_, err := tvu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tvu *TemplateVersionUpdate) ExecX(ctx context.Context) {
	if err := tvu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (tvu *TemplateVersionUpdate) defaults() error {
	if _, ok := tvu.mutation.UpdateTime(); !ok {
		if templateversion.UpdateDefaultUpdateTime == nil {
			return fmt.Errorf("model: uninitialized templateversion.UpdateDefaultUpdateTime (forgotten import model/runtime?)")
		}
		v := templateversion.UpdateDefaultUpdateTime()
		tvu.mutation.SetUpdateTime(v)
	}
	return nil
}

// check runs all checks and user-defined validators on the builder.
func (tvu *TemplateVersionUpdate) check() error {
	if v, ok := tvu.mutation.Schema(); ok {
		if err := v.Validate(); err != nil {
			return &ValidationError{Name: "schema", err: fmt.Errorf(`model: validator failed for field "TemplateVersion.schema": %w`, err)}
		}
	}
	if _, ok := tvu.mutation.TemplateID(); tvu.mutation.TemplateCleared() && !ok {
		return errors.New(`model: clearing a required unique edge "TemplateVersion.template"`)
	}
	return nil
}

// Set is different from other Set* methods,
// it sets the value by judging the definition of each field within the entire object.
//
// For default fields, Set calls if the value is not zero.
//
// For no default but required fields, Set calls directly.
//
// For no default but optional fields, Set calls if the value is not zero,
// or clears if the value is zero.
//
// For example:
//
//	## Without Default
//
//	### Required
//
//	db.SetX(obj.X)
//
//	### Optional or Default
//
//	if _is_zero_value_(obj.X) {
//	   db.SetX(obj.X)
//	} else {
//	   db.ClearX()
//	}
//
//	## With Default
//
//	if _is_zero_value_(obj.X) {
//	   db.SetX(obj.X)
//	}
func (tvu *TemplateVersionUpdate) Set(obj *TemplateVersion) *TemplateVersionUpdate {
	// Without Default.
	tvu.SetSchema(obj.Schema)
	tvu.SetUiSchema(obj.UiSchema)
	if !reflect.ValueOf(obj.SchemaDefaultValue).IsZero() {
		tvu.SetSchemaDefaultValue(obj.SchemaDefaultValue)
	}

	// With Default.
	if obj.UpdateTime != nil {
		tvu.SetUpdateTime(*obj.UpdateTime)
	}

	// Record the given object.
	tvu.object = obj

	return tvu
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (tvu *TemplateVersionUpdate) Modify(modifiers ...func(u *sql.UpdateBuilder)) *TemplateVersionUpdate {
	tvu.modifiers = append(tvu.modifiers, modifiers...)
	return tvu
}

func (tvu *TemplateVersionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := tvu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(templateversion.Table, templateversion.Columns, sqlgraph.NewFieldSpec(templateversion.FieldID, field.TypeString))
	if ps := tvu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tvu.mutation.UpdateTime(); ok {
		_spec.SetField(templateversion.FieldUpdateTime, field.TypeTime, value)
	}
	if value, ok := tvu.mutation.Schema(); ok {
		_spec.SetField(templateversion.FieldSchema, field.TypeJSON, value)
	}
	if value, ok := tvu.mutation.UiSchema(); ok {
		_spec.SetField(templateversion.FieldUiSchema, field.TypeJSON, value)
	}
	if value, ok := tvu.mutation.SchemaDefaultValue(); ok {
		_spec.SetField(templateversion.FieldSchemaDefaultValue, field.TypeBytes, value)
	}
	if tvu.mutation.SchemaDefaultValueCleared() {
		_spec.ClearField(templateversion.FieldSchemaDefaultValue, field.TypeBytes)
	}
	if tvu.mutation.ResourcesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   templateversion.ResourcesTable,
			Columns: []string{templateversion.ResourcesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resource.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvu.schemaConfig.Resource
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvu.mutation.RemovedResourcesIDs(); len(nodes) > 0 && !tvu.mutation.ResourcesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   templateversion.ResourcesTable,
			Columns: []string{templateversion.ResourcesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resource.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvu.schemaConfig.Resource
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvu.mutation.ResourcesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   templateversion.ResourcesTable,
			Columns: []string{templateversion.ResourcesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resource.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvu.schemaConfig.Resource
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tvu.mutation.ResourceDefinitionsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   templateversion.ResourceDefinitionsTable,
			Columns: []string{templateversion.ResourceDefinitionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resourcedefinitionmatchingrule.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvu.schemaConfig.ResourceDefinitionMatchingRule
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvu.mutation.RemovedResourceDefinitionsIDs(); len(nodes) > 0 && !tvu.mutation.ResourceDefinitionsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   templateversion.ResourceDefinitionsTable,
			Columns: []string{templateversion.ResourceDefinitionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resourcedefinitionmatchingrule.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvu.schemaConfig.ResourceDefinitionMatchingRule
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvu.mutation.ResourceDefinitionsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   templateversion.ResourceDefinitionsTable,
			Columns: []string{templateversion.ResourceDefinitionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resourcedefinitionmatchingrule.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvu.schemaConfig.ResourceDefinitionMatchingRule
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.Node.Schema = tvu.schemaConfig.TemplateVersion
	ctx = internal.NewSchemaConfigContext(ctx, tvu.schemaConfig)
	_spec.AddModifiers(tvu.modifiers...)
	if n, err = sqlgraph.UpdateNodes(ctx, tvu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{templateversion.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	tvu.mutation.done = true
	return n, nil
}

// TemplateVersionUpdateOne is the builder for updating a single TemplateVersion entity.
type TemplateVersionUpdateOne struct {
	config
	fields    []string
	hooks     []Hook
	mutation  *TemplateVersionMutation
	modifiers []func(*sql.UpdateBuilder)
	object    *TemplateVersion
}

// SetUpdateTime sets the "update_time" field.
func (tvuo *TemplateVersionUpdateOne) SetUpdateTime(t time.Time) *TemplateVersionUpdateOne {
	tvuo.mutation.SetUpdateTime(t)
	return tvuo
}

// SetSchema sets the "schema" field.
func (tvuo *TemplateVersionUpdateOne) SetSchema(tvs types.TemplateVersionSchema) *TemplateVersionUpdateOne {
	tvuo.mutation.SetSchema(tvs)
	return tvuo
}

// SetNillableSchema sets the "schema" field if the given value is not nil.
func (tvuo *TemplateVersionUpdateOne) SetNillableSchema(tvs *types.TemplateVersionSchema) *TemplateVersionUpdateOne {
	if tvs != nil {
		tvuo.SetSchema(*tvs)
	}
	return tvuo
}

// SetUiSchema sets the "uiSchema" field.
func (tvuo *TemplateVersionUpdateOne) SetUiSchema(ts types.UISchema) *TemplateVersionUpdateOne {
	tvuo.mutation.SetUiSchema(ts)
	return tvuo
}

// SetNillableUiSchema sets the "uiSchema" field if the given value is not nil.
func (tvuo *TemplateVersionUpdateOne) SetNillableUiSchema(ts *types.UISchema) *TemplateVersionUpdateOne {
	if ts != nil {
		tvuo.SetUiSchema(*ts)
	}
	return tvuo
}

// SetSchemaDefaultValue sets the "schema_default_value" field.
func (tvuo *TemplateVersionUpdateOne) SetSchemaDefaultValue(b []byte) *TemplateVersionUpdateOne {
	tvuo.mutation.SetSchemaDefaultValue(b)
	return tvuo
}

// ClearSchemaDefaultValue clears the value of the "schema_default_value" field.
func (tvuo *TemplateVersionUpdateOne) ClearSchemaDefaultValue() *TemplateVersionUpdateOne {
	tvuo.mutation.ClearSchemaDefaultValue()
	return tvuo
}

// AddResourceIDs adds the "resources" edge to the Resource entity by IDs.
func (tvuo *TemplateVersionUpdateOne) AddResourceIDs(ids ...object.ID) *TemplateVersionUpdateOne {
	tvuo.mutation.AddResourceIDs(ids...)
	return tvuo
}

// AddResources adds the "resources" edges to the Resource entity.
func (tvuo *TemplateVersionUpdateOne) AddResources(r ...*Resource) *TemplateVersionUpdateOne {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvuo.AddResourceIDs(ids...)
}

// AddResourceDefinitionIDs adds the "resource_definitions" edge to the ResourceDefinitionMatchingRule entity by IDs.
func (tvuo *TemplateVersionUpdateOne) AddResourceDefinitionIDs(ids ...object.ID) *TemplateVersionUpdateOne {
	tvuo.mutation.AddResourceDefinitionIDs(ids...)
	return tvuo
}

// AddResourceDefinitions adds the "resource_definitions" edges to the ResourceDefinitionMatchingRule entity.
func (tvuo *TemplateVersionUpdateOne) AddResourceDefinitions(r ...*ResourceDefinitionMatchingRule) *TemplateVersionUpdateOne {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvuo.AddResourceDefinitionIDs(ids...)
}

// Mutation returns the TemplateVersionMutation object of the builder.
func (tvuo *TemplateVersionUpdateOne) Mutation() *TemplateVersionMutation {
	return tvuo.mutation
}

// ClearResources clears all "resources" edges to the Resource entity.
func (tvuo *TemplateVersionUpdateOne) ClearResources() *TemplateVersionUpdateOne {
	tvuo.mutation.ClearResources()
	return tvuo
}

// RemoveResourceIDs removes the "resources" edge to Resource entities by IDs.
func (tvuo *TemplateVersionUpdateOne) RemoveResourceIDs(ids ...object.ID) *TemplateVersionUpdateOne {
	tvuo.mutation.RemoveResourceIDs(ids...)
	return tvuo
}

// RemoveResources removes "resources" edges to Resource entities.
func (tvuo *TemplateVersionUpdateOne) RemoveResources(r ...*Resource) *TemplateVersionUpdateOne {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvuo.RemoveResourceIDs(ids...)
}

// ClearResourceDefinitions clears all "resource_definitions" edges to the ResourceDefinitionMatchingRule entity.
func (tvuo *TemplateVersionUpdateOne) ClearResourceDefinitions() *TemplateVersionUpdateOne {
	tvuo.mutation.ClearResourceDefinitions()
	return tvuo
}

// RemoveResourceDefinitionIDs removes the "resource_definitions" edge to ResourceDefinitionMatchingRule entities by IDs.
func (tvuo *TemplateVersionUpdateOne) RemoveResourceDefinitionIDs(ids ...object.ID) *TemplateVersionUpdateOne {
	tvuo.mutation.RemoveResourceDefinitionIDs(ids...)
	return tvuo
}

// RemoveResourceDefinitions removes "resource_definitions" edges to ResourceDefinitionMatchingRule entities.
func (tvuo *TemplateVersionUpdateOne) RemoveResourceDefinitions(r ...*ResourceDefinitionMatchingRule) *TemplateVersionUpdateOne {
	ids := make([]object.ID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return tvuo.RemoveResourceDefinitionIDs(ids...)
}

// Where appends a list predicates to the TemplateVersionUpdate builder.
func (tvuo *TemplateVersionUpdateOne) Where(ps ...predicate.TemplateVersion) *TemplateVersionUpdateOne {
	tvuo.mutation.Where(ps...)
	return tvuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (tvuo *TemplateVersionUpdateOne) Select(field string, fields ...string) *TemplateVersionUpdateOne {
	tvuo.fields = append([]string{field}, fields...)
	return tvuo
}

// Save executes the query and returns the updated TemplateVersion entity.
func (tvuo *TemplateVersionUpdateOne) Save(ctx context.Context) (*TemplateVersion, error) {
	if err := tvuo.defaults(); err != nil {
		return nil, err
	}
	return withHooks(ctx, tvuo.sqlSave, tvuo.mutation, tvuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (tvuo *TemplateVersionUpdateOne) SaveX(ctx context.Context) *TemplateVersion {
	node, err := tvuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (tvuo *TemplateVersionUpdateOne) Exec(ctx context.Context) error {
	_, err := tvuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tvuo *TemplateVersionUpdateOne) ExecX(ctx context.Context) {
	if err := tvuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (tvuo *TemplateVersionUpdateOne) defaults() error {
	if _, ok := tvuo.mutation.UpdateTime(); !ok {
		if templateversion.UpdateDefaultUpdateTime == nil {
			return fmt.Errorf("model: uninitialized templateversion.UpdateDefaultUpdateTime (forgotten import model/runtime?)")
		}
		v := templateversion.UpdateDefaultUpdateTime()
		tvuo.mutation.SetUpdateTime(v)
	}
	return nil
}

// check runs all checks and user-defined validators on the builder.
func (tvuo *TemplateVersionUpdateOne) check() error {
	if v, ok := tvuo.mutation.Schema(); ok {
		if err := v.Validate(); err != nil {
			return &ValidationError{Name: "schema", err: fmt.Errorf(`model: validator failed for field "TemplateVersion.schema": %w`, err)}
		}
	}
	if _, ok := tvuo.mutation.TemplateID(); tvuo.mutation.TemplateCleared() && !ok {
		return errors.New(`model: clearing a required unique edge "TemplateVersion.template"`)
	}
	return nil
}

// Set is different from other Set* methods,
// it sets the value by judging the definition of each field within the entire object.
//
// For default fields, Set calls if the value changes from the original.
//
// For no default but required fields, Set calls if the value changes from the original.
//
// For no default but optional fields, Set calls if the value changes from the original,
// or clears if changes to zero.
//
// For example:
//
//	## Without Default
//
//	### Required
//
//	db.SetX(obj.X)
//
//	### Optional or Default
//
//	if _is_zero_value_(obj.X) {
//	   if _is_not_equal_(db.X, obj.X) {
//	      db.SetX(obj.X)
//	   }
//	} else {
//	   db.ClearX()
//	}
//
//	## With Default
//
//	if _is_zero_value_(obj.X) && _is_not_equal_(db.X, obj.X) {
//	   db.SetX(obj.X)
//	}
func (tvuo *TemplateVersionUpdateOne) Set(obj *TemplateVersion) *TemplateVersionUpdateOne {
	h := func(n ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			mt := m.(*TemplateVersionMutation)
			db, err := mt.Client().TemplateVersion.Get(ctx, *mt.id)
			if err != nil {
				return nil, fmt.Errorf("failed getting TemplateVersion with id: %v", *mt.id)
			}

			// Without Default.
			if !reflect.DeepEqual(db.Schema, obj.Schema) {
				tvuo.SetSchema(obj.Schema)
			}
			if !reflect.DeepEqual(db.UiSchema, obj.UiSchema) {
				tvuo.SetUiSchema(obj.UiSchema)
			}
			if !reflect.ValueOf(obj.SchemaDefaultValue).IsZero() {
				if !bytes.Equal(db.SchemaDefaultValue, obj.SchemaDefaultValue) {
					tvuo.SetSchemaDefaultValue(obj.SchemaDefaultValue)
				}
			}

			// With Default.
			if (obj.UpdateTime != nil) && (!reflect.DeepEqual(db.UpdateTime, obj.UpdateTime)) {
				tvuo.SetUpdateTime(*obj.UpdateTime)
			}

			// Record the given object.
			tvuo.object = obj

			return n.Mutate(ctx, m)
		})
	}

	tvuo.hooks = append(tvuo.hooks, h)

	return tvuo
}

// getClientSet returns the ClientSet for the given builder.
func (tvuo *TemplateVersionUpdateOne) getClientSet() (mc ClientSet) {
	if _, ok := tvuo.config.driver.(*txDriver); ok {
		tx := &Tx{config: tvuo.config}
		tx.init()
		mc = tx
	} else {
		cli := &Client{config: tvuo.config}
		cli.init()
		mc = cli
	}
	return mc
}

// SaveE calls the given function after updated the TemplateVersion entity,
// which is always good for cascading update operations.
func (tvuo *TemplateVersionUpdateOne) SaveE(ctx context.Context, cbs ...func(ctx context.Context, mc ClientSet, updated *TemplateVersion) error) (*TemplateVersion, error) {
	obj, err := tvuo.Save(ctx)
	if err != nil &&
		(tvuo.object == nil || !errors.Is(err, stdsql.ErrNoRows)) {
		return nil, err
	}

	if len(cbs) == 0 {
		return obj, err
	}

	mc := tvuo.getClientSet()

	if obj == nil {
		obj = tvuo.object
	} else if x := tvuo.object; x != nil {
		if _, set := tvuo.mutation.Field(templateversion.FieldSchema); set {
			obj.Schema = x.Schema
		}
		if _, set := tvuo.mutation.Field(templateversion.FieldUiSchema); set {
			obj.UiSchema = x.UiSchema
		}
		if _, set := tvuo.mutation.Field(templateversion.FieldSchemaDefaultValue); set {
			obj.SchemaDefaultValue = x.SchemaDefaultValue
		}
		obj.Edges = x.Edges
	}

	for i := range cbs {
		if err = cbs[i](ctx, mc, obj); err != nil {
			return nil, err
		}
	}

	return obj, nil
}

// SaveEX is like SaveE, but panics if an error occurs.
func (tvuo *TemplateVersionUpdateOne) SaveEX(ctx context.Context, cbs ...func(ctx context.Context, mc ClientSet, updated *TemplateVersion) error) *TemplateVersion {
	obj, err := tvuo.SaveE(ctx, cbs...)
	if err != nil {
		panic(err)
	}
	return obj
}

// ExecE calls the given function after executed the query,
// which is always good for cascading update operations.
func (tvuo *TemplateVersionUpdateOne) ExecE(ctx context.Context, cbs ...func(ctx context.Context, mc ClientSet, updated *TemplateVersion) error) error {
	_, err := tvuo.SaveE(ctx, cbs...)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tvuo *TemplateVersionUpdateOne) ExecEX(ctx context.Context, cbs ...func(ctx context.Context, mc ClientSet, updated *TemplateVersion) error) {
	if err := tvuo.ExecE(ctx, cbs...); err != nil {
		panic(err)
	}
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (tvuo *TemplateVersionUpdateOne) Modify(modifiers ...func(u *sql.UpdateBuilder)) *TemplateVersionUpdateOne {
	tvuo.modifiers = append(tvuo.modifiers, modifiers...)
	return tvuo
}

func (tvuo *TemplateVersionUpdateOne) sqlSave(ctx context.Context) (_node *TemplateVersion, err error) {
	if err := tvuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(templateversion.Table, templateversion.Columns, sqlgraph.NewFieldSpec(templateversion.FieldID, field.TypeString))
	id, ok := tvuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`model: missing "TemplateVersion.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := tvuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, templateversion.FieldID)
		for _, f := range fields {
			if !templateversion.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("model: invalid field %q for query", f)}
			}
			if f != templateversion.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := tvuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tvuo.mutation.UpdateTime(); ok {
		_spec.SetField(templateversion.FieldUpdateTime, field.TypeTime, value)
	}
	if value, ok := tvuo.mutation.Schema(); ok {
		_spec.SetField(templateversion.FieldSchema, field.TypeJSON, value)
	}
	if value, ok := tvuo.mutation.UiSchema(); ok {
		_spec.SetField(templateversion.FieldUiSchema, field.TypeJSON, value)
	}
	if value, ok := tvuo.mutation.SchemaDefaultValue(); ok {
		_spec.SetField(templateversion.FieldSchemaDefaultValue, field.TypeBytes, value)
	}
	if tvuo.mutation.SchemaDefaultValueCleared() {
		_spec.ClearField(templateversion.FieldSchemaDefaultValue, field.TypeBytes)
	}
	if tvuo.mutation.ResourcesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   templateversion.ResourcesTable,
			Columns: []string{templateversion.ResourcesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resource.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvuo.schemaConfig.Resource
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvuo.mutation.RemovedResourcesIDs(); len(nodes) > 0 && !tvuo.mutation.ResourcesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   templateversion.ResourcesTable,
			Columns: []string{templateversion.ResourcesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resource.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvuo.schemaConfig.Resource
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvuo.mutation.ResourcesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   templateversion.ResourcesTable,
			Columns: []string{templateversion.ResourcesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resource.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvuo.schemaConfig.Resource
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tvuo.mutation.ResourceDefinitionsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   templateversion.ResourceDefinitionsTable,
			Columns: []string{templateversion.ResourceDefinitionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resourcedefinitionmatchingrule.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvuo.schemaConfig.ResourceDefinitionMatchingRule
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvuo.mutation.RemovedResourceDefinitionsIDs(); len(nodes) > 0 && !tvuo.mutation.ResourceDefinitionsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   templateversion.ResourceDefinitionsTable,
			Columns: []string{templateversion.ResourceDefinitionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resourcedefinitionmatchingrule.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvuo.schemaConfig.ResourceDefinitionMatchingRule
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tvuo.mutation.ResourceDefinitionsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   templateversion.ResourceDefinitionsTable,
			Columns: []string{templateversion.ResourceDefinitionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(resourcedefinitionmatchingrule.FieldID, field.TypeString),
			},
		}
		edge.Schema = tvuo.schemaConfig.ResourceDefinitionMatchingRule
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.Node.Schema = tvuo.schemaConfig.TemplateVersion
	ctx = internal.NewSchemaConfigContext(ctx, tvuo.schemaConfig)
	_spec.AddModifiers(tvuo.modifiers...)
	_node = &TemplateVersion{config: tvuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, tvuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{templateversion.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	tvuo.mutation.done = true
	return _node, nil
}
