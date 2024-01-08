// SPDX-FileCopyrightText: 2023 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus". DO NOT EDIT.

package resourcedefinitionmatchingrule

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"

	"github.com/seal-io/walrus/pkg/dao/model/internal"
	"github.com/seal-io/walrus/pkg/dao/model/predicate"
	"github.com/seal-io/walrus/pkg/dao/types/object"
	"github.com/seal-io/walrus/pkg/dao/types/property"
)

// ID filters vertices based on their ID field.
func ID(id object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldID, id))
}

// CreateTime applies equality check predicate on the "create_time" field. It's identical to CreateTimeEQ.
func CreateTime(v time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldCreateTime, v))
}

// ResourceDefinitionID applies equality check predicate on the "resource_definition_id" field. It's identical to ResourceDefinitionIDEQ.
func ResourceDefinitionID(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldResourceDefinitionID, v))
}

// TemplateID applies equality check predicate on the "template_id" field. It's identical to TemplateIDEQ.
func TemplateID(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldTemplateID, v))
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldName, v))
}

// Attributes applies equality check predicate on the "attributes" field. It's identical to AttributesEQ.
func Attributes(v property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldAttributes, v))
}

// Order applies equality check predicate on the "order" field. It's identical to OrderEQ.
func Order(v int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldOrder, v))
}

// SchemaDefaultValue applies equality check predicate on the "schema_default_value" field. It's identical to SchemaDefaultValueEQ.
func SchemaDefaultValue(v []byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldSchemaDefaultValue, v))
}

// CreateTimeEQ applies the EQ predicate on the "create_time" field.
func CreateTimeEQ(v time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldCreateTime, v))
}

// CreateTimeNEQ applies the NEQ predicate on the "create_time" field.
func CreateTimeNEQ(v time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldCreateTime, v))
}

// CreateTimeIn applies the In predicate on the "create_time" field.
func CreateTimeIn(vs ...time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldCreateTime, vs...))
}

// CreateTimeNotIn applies the NotIn predicate on the "create_time" field.
func CreateTimeNotIn(vs ...time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldCreateTime, vs...))
}

// CreateTimeGT applies the GT predicate on the "create_time" field.
func CreateTimeGT(v time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldCreateTime, v))
}

// CreateTimeGTE applies the GTE predicate on the "create_time" field.
func CreateTimeGTE(v time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldCreateTime, v))
}

// CreateTimeLT applies the LT predicate on the "create_time" field.
func CreateTimeLT(v time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldCreateTime, v))
}

// CreateTimeLTE applies the LTE predicate on the "create_time" field.
func CreateTimeLTE(v time.Time) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldCreateTime, v))
}

// ResourceDefinitionIDEQ applies the EQ predicate on the "resource_definition_id" field.
func ResourceDefinitionIDEQ(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldResourceDefinitionID, v))
}

// ResourceDefinitionIDNEQ applies the NEQ predicate on the "resource_definition_id" field.
func ResourceDefinitionIDNEQ(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldResourceDefinitionID, v))
}

// ResourceDefinitionIDIn applies the In predicate on the "resource_definition_id" field.
func ResourceDefinitionIDIn(vs ...object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldResourceDefinitionID, vs...))
}

// ResourceDefinitionIDNotIn applies the NotIn predicate on the "resource_definition_id" field.
func ResourceDefinitionIDNotIn(vs ...object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldResourceDefinitionID, vs...))
}

// ResourceDefinitionIDGT applies the GT predicate on the "resource_definition_id" field.
func ResourceDefinitionIDGT(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldResourceDefinitionID, v))
}

// ResourceDefinitionIDGTE applies the GTE predicate on the "resource_definition_id" field.
func ResourceDefinitionIDGTE(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldResourceDefinitionID, v))
}

// ResourceDefinitionIDLT applies the LT predicate on the "resource_definition_id" field.
func ResourceDefinitionIDLT(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldResourceDefinitionID, v))
}

// ResourceDefinitionIDLTE applies the LTE predicate on the "resource_definition_id" field.
func ResourceDefinitionIDLTE(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldResourceDefinitionID, v))
}

// ResourceDefinitionIDContains applies the Contains predicate on the "resource_definition_id" field.
func ResourceDefinitionIDContains(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldContains(FieldResourceDefinitionID, vc))
}

// ResourceDefinitionIDHasPrefix applies the HasPrefix predicate on the "resource_definition_id" field.
func ResourceDefinitionIDHasPrefix(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldHasPrefix(FieldResourceDefinitionID, vc))
}

// ResourceDefinitionIDHasSuffix applies the HasSuffix predicate on the "resource_definition_id" field.
func ResourceDefinitionIDHasSuffix(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldHasSuffix(FieldResourceDefinitionID, vc))
}

// ResourceDefinitionIDEqualFold applies the EqualFold predicate on the "resource_definition_id" field.
func ResourceDefinitionIDEqualFold(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEqualFold(FieldResourceDefinitionID, vc))
}

// ResourceDefinitionIDContainsFold applies the ContainsFold predicate on the "resource_definition_id" field.
func ResourceDefinitionIDContainsFold(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldContainsFold(FieldResourceDefinitionID, vc))
}

// TemplateIDEQ applies the EQ predicate on the "template_id" field.
func TemplateIDEQ(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldTemplateID, v))
}

// TemplateIDNEQ applies the NEQ predicate on the "template_id" field.
func TemplateIDNEQ(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldTemplateID, v))
}

// TemplateIDIn applies the In predicate on the "template_id" field.
func TemplateIDIn(vs ...object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldTemplateID, vs...))
}

// TemplateIDNotIn applies the NotIn predicate on the "template_id" field.
func TemplateIDNotIn(vs ...object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldTemplateID, vs...))
}

// TemplateIDGT applies the GT predicate on the "template_id" field.
func TemplateIDGT(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldTemplateID, v))
}

// TemplateIDGTE applies the GTE predicate on the "template_id" field.
func TemplateIDGTE(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldTemplateID, v))
}

// TemplateIDLT applies the LT predicate on the "template_id" field.
func TemplateIDLT(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldTemplateID, v))
}

// TemplateIDLTE applies the LTE predicate on the "template_id" field.
func TemplateIDLTE(v object.ID) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldTemplateID, v))
}

// TemplateIDContains applies the Contains predicate on the "template_id" field.
func TemplateIDContains(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldContains(FieldTemplateID, vc))
}

// TemplateIDHasPrefix applies the HasPrefix predicate on the "template_id" field.
func TemplateIDHasPrefix(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldHasPrefix(FieldTemplateID, vc))
}

// TemplateIDHasSuffix applies the HasSuffix predicate on the "template_id" field.
func TemplateIDHasSuffix(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldHasSuffix(FieldTemplateID, vc))
}

// TemplateIDEqualFold applies the EqualFold predicate on the "template_id" field.
func TemplateIDEqualFold(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEqualFold(FieldTemplateID, vc))
}

// TemplateIDContainsFold applies the ContainsFold predicate on the "template_id" field.
func TemplateIDContainsFold(v object.ID) predicate.ResourceDefinitionMatchingRule {
	vc := string(v)
	return predicate.ResourceDefinitionMatchingRule(sql.FieldContainsFold(FieldTemplateID, vc))
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldName, v))
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldName, v))
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldName, vs...))
}

// NameNotIn applies the NotIn predicate on the "name" field.
func NameNotIn(vs ...string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldName, vs...))
}

// NameGT applies the GT predicate on the "name" field.
func NameGT(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldName, v))
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldName, v))
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldName, v))
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldName, v))
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldContains(FieldName, v))
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldHasPrefix(FieldName, v))
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldHasSuffix(FieldName, v))
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEqualFold(FieldName, v))
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldContainsFold(FieldName, v))
}

// AttributesEQ applies the EQ predicate on the "attributes" field.
func AttributesEQ(v property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldAttributes, v))
}

// AttributesNEQ applies the NEQ predicate on the "attributes" field.
func AttributesNEQ(v property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldAttributes, v))
}

// AttributesIn applies the In predicate on the "attributes" field.
func AttributesIn(vs ...property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldAttributes, vs...))
}

// AttributesNotIn applies the NotIn predicate on the "attributes" field.
func AttributesNotIn(vs ...property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldAttributes, vs...))
}

// AttributesGT applies the GT predicate on the "attributes" field.
func AttributesGT(v property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldAttributes, v))
}

// AttributesGTE applies the GTE predicate on the "attributes" field.
func AttributesGTE(v property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldAttributes, v))
}

// AttributesLT applies the LT predicate on the "attributes" field.
func AttributesLT(v property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldAttributes, v))
}

// AttributesLTE applies the LTE predicate on the "attributes" field.
func AttributesLTE(v property.Values) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldAttributes, v))
}

// AttributesIsNil applies the IsNil predicate on the "attributes" field.
func AttributesIsNil() predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIsNull(FieldAttributes))
}

// AttributesNotNil applies the NotNil predicate on the "attributes" field.
func AttributesNotNil() predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotNull(FieldAttributes))
}

// OrderEQ applies the EQ predicate on the "order" field.
func OrderEQ(v int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldOrder, v))
}

// OrderNEQ applies the NEQ predicate on the "order" field.
func OrderNEQ(v int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldOrder, v))
}

// OrderIn applies the In predicate on the "order" field.
func OrderIn(vs ...int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldOrder, vs...))
}

// OrderNotIn applies the NotIn predicate on the "order" field.
func OrderNotIn(vs ...int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldOrder, vs...))
}

// OrderGT applies the GT predicate on the "order" field.
func OrderGT(v int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldOrder, v))
}

// OrderGTE applies the GTE predicate on the "order" field.
func OrderGTE(v int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldOrder, v))
}

// OrderLT applies the LT predicate on the "order" field.
func OrderLT(v int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldOrder, v))
}

// OrderLTE applies the LTE predicate on the "order" field.
func OrderLTE(v int) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldOrder, v))
}

// SchemaDefaultValueEQ applies the EQ predicate on the "schema_default_value" field.
func SchemaDefaultValueEQ(v []byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldEQ(FieldSchemaDefaultValue, v))
}

// SchemaDefaultValueNEQ applies the NEQ predicate on the "schema_default_value" field.
func SchemaDefaultValueNEQ(v []byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNEQ(FieldSchemaDefaultValue, v))
}

// SchemaDefaultValueIn applies the In predicate on the "schema_default_value" field.
func SchemaDefaultValueIn(vs ...[]byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIn(FieldSchemaDefaultValue, vs...))
}

// SchemaDefaultValueNotIn applies the NotIn predicate on the "schema_default_value" field.
func SchemaDefaultValueNotIn(vs ...[]byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotIn(FieldSchemaDefaultValue, vs...))
}

// SchemaDefaultValueGT applies the GT predicate on the "schema_default_value" field.
func SchemaDefaultValueGT(v []byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGT(FieldSchemaDefaultValue, v))
}

// SchemaDefaultValueGTE applies the GTE predicate on the "schema_default_value" field.
func SchemaDefaultValueGTE(v []byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldGTE(FieldSchemaDefaultValue, v))
}

// SchemaDefaultValueLT applies the LT predicate on the "schema_default_value" field.
func SchemaDefaultValueLT(v []byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLT(FieldSchemaDefaultValue, v))
}

// SchemaDefaultValueLTE applies the LTE predicate on the "schema_default_value" field.
func SchemaDefaultValueLTE(v []byte) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldLTE(FieldSchemaDefaultValue, v))
}

// SchemaDefaultValueIsNil applies the IsNil predicate on the "schema_default_value" field.
func SchemaDefaultValueIsNil() predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldIsNull(FieldSchemaDefaultValue))
}

// SchemaDefaultValueNotNil applies the NotNil predicate on the "schema_default_value" field.
func SchemaDefaultValueNotNil() predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(sql.FieldNotNull(FieldSchemaDefaultValue))
}

// HasResourceDefinition applies the HasEdge predicate on the "resource_definition" edge.
func HasResourceDefinition() predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, ResourceDefinitionTable, ResourceDefinitionColumn),
		)
		schemaConfig := internal.SchemaConfigFromContext(s.Context())
		step.To.Schema = schemaConfig.ResourceDefinition
		step.Edge.Schema = schemaConfig.ResourceDefinitionMatchingRule
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasResourceDefinitionWith applies the HasEdge predicate on the "resource_definition" edge with a given conditions (other predicates).
func HasResourceDefinitionWith(preds ...predicate.ResourceDefinition) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		step := newResourceDefinitionStep()
		schemaConfig := internal.SchemaConfigFromContext(s.Context())
		step.To.Schema = schemaConfig.ResourceDefinition
		step.Edge.Schema = schemaConfig.ResourceDefinitionMatchingRule
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasTemplate applies the HasEdge predicate on the "template" edge.
func HasTemplate() predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, TemplateTable, TemplateColumn),
		)
		schemaConfig := internal.SchemaConfigFromContext(s.Context())
		step.To.Schema = schemaConfig.TemplateVersion
		step.Edge.Schema = schemaConfig.ResourceDefinitionMatchingRule
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasTemplateWith applies the HasEdge predicate on the "template" edge with a given conditions (other predicates).
func HasTemplateWith(preds ...predicate.TemplateVersion) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		step := newTemplateStep()
		schemaConfig := internal.SchemaConfigFromContext(s.Context())
		step.To.Schema = schemaConfig.TemplateVersion
		step.Edge.Schema = schemaConfig.ResourceDefinitionMatchingRule
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasResources applies the HasEdge predicate on the "resources" edge.
func HasResources() predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, ResourcesTable, ResourcesColumn),
		)
		schemaConfig := internal.SchemaConfigFromContext(s.Context())
		step.To.Schema = schemaConfig.Resource
		step.Edge.Schema = schemaConfig.Resource
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasResourcesWith applies the HasEdge predicate on the "resources" edge with a given conditions (other predicates).
func HasResourcesWith(preds ...predicate.Resource) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		step := newResourcesStep()
		schemaConfig := internal.SchemaConfigFromContext(s.Context())
		step.To.Schema = schemaConfig.Resource
		step.Edge.Schema = schemaConfig.Resource
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.ResourceDefinitionMatchingRule) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.ResourceDefinitionMatchingRule) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.ResourceDefinitionMatchingRule) predicate.ResourceDefinitionMatchingRule {
	return predicate.ResourceDefinitionMatchingRule(func(s *sql.Selector) {
		p(s.Not())
	})
}
