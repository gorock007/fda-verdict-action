import { z } from "zod";

// Branded uuids: passing a customer id where an org id belongs is a type
// error. Rows read from the db are parsed (or cast) once at that boundary.
export const organizationIdSchema = z.uuid().brand<"OrganizationId">();
export const customerIdSchema = z.uuid().brand<"CustomerId">();
export const endUserIdSchema = z.uuid().brand<"EndUserId">();
export const operatorUserIdSchema = z.uuid().brand<"OperatorUserId">();
export const repositoryIdSchema = z.uuid().brand<"RepositoryId">();
export const requestIdSchema = z.uuid().brand<"RequestId">();
export const intentIdSchema = z.uuid().brand<"IntentId">();
export const acceptanceSpecIdSchema = z.uuid().brand<"AcceptanceSpecId">();
export const taskIdSchema = z.uuid().brand<"TaskId">();

export type OrganizationId = z.infer<typeof organizationIdSchema>;
export type CustomerId = z.infer<typeof customerIdSchema>;
export type EndUserId = z.infer<typeof endUserIdSchema>;
export type OperatorUserId = z.infer<typeof operatorUserIdSchema>;
export type RepositoryId = z.infer<typeof repositoryIdSchema>;
export type RequestId = z.infer<typeof requestIdSchema>;
export type IntentId = z.infer<typeof intentIdSchema>;
export type AcceptanceSpecId = z.infer<typeof acceptanceSpecIdSchema>;
export type TaskId = z.infer<typeof taskIdSchema>;
