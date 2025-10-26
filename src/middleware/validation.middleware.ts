import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';
import { ValidationError } from '../utils/errors';

/**
 * Validation middleware factory
 * Creates middleware to validate request data against Zod schemas
 */
export const validate = (
  schema: ZodSchema,
  target: 'body' | 'params' | 'query' = 'body'
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const dataToValidate = req[target];
      
      // Parse and validate the data
      const validatedData = schema.parse(dataToValidate);
      
      // Replace the original data with validated data
      req[target] = validatedData;
      
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const validationErrors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          code: err.code,
        }));

        const validationError = new ValidationError(
          'Validation failed',
          validationErrors
        );
        
        next(validationError);
      } else {
        next(error);
      }
    }
  };
};

/**
 * Validate request body
 */
export const validateBody = (schema: ZodSchema) => validate(schema, 'body');

/**
 * Validate request params
 */
export const validateParams = (schema: ZodSchema) => validate(schema, 'params');

/**
 * Validate request query
 */
export const validateQuery = (schema: ZodSchema) => validate(schema, 'query');

/**
 * Validate multiple parts of the request
 */
export const validateRequest = (schemas: {
  body?: ZodSchema;
  params?: ZodSchema;
  query?: ZodSchema;
}) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const errors: { location: string; field: string; message: string }[] = [];

      // Validate body if schema provided
      if (schemas.body) {
        try {
          req.body = schemas.body.parse(req.body);
        } catch (error) {
          if (error instanceof ZodError) {
            errors.push(...error.errors.map(err => ({
              location: 'body',
              field: err.path.join('.'),
              message: err.message,
              code: err.code,
            })));
          }
        }
      }

      // Validate params if schema provided
      if (schemas.params) {
        try {
          req.params = schemas.params.parse(req.params);
        } catch (error) {
          if (error instanceof ZodError) {
            errors.push(...error.errors.map(err => ({
              location: 'params',
              field: err.path.join('.'),
              message: err.message,
              code: err.code,
            })));
          }
        }
      }

      // Validate query if schema provided
      if (schemas.query) {
        try {
          req.query = schemas.query.parse(req.query);
        } catch (error) {
          if (error instanceof ZodError) {
            errors.push(...error.errors.map(err => ({
              location: 'query',
              field: err.path.join('.'),
              message: err.message,
              code: err.code,
            })));
          }
        }
      }

      // If there are validation errors, throw ValidationError
      if (errors.length > 0) {
        const validationError = new ValidationError(
          'Request validation failed',
          errors
        );
        
        return next(validationError);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
