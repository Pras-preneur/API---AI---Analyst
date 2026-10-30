import type { ApiSpec } from '../types/assistant';

const DEMO_API_YAML = `openapi: 3.0.0
info:
  title: Demo API
  version: "1.0"
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
  parameters:
    LimitParam:
      name: limit
      in: query
      schema:
        type: integer
        default: 10
security:
  - BearerAuth: []
paths:
  /users:
    get:
      summary: List users
      operationId: listUsers
      parameters:
        - $ref: "#/components/parameters/LimitParam"
      responses:
        "200":
          description: A list of users.
    post:
      summary: Create a user
      operationId: createUser
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: User created.
  /users/{user_id}:
    parameters:
      - name: user_id
        in: path
        required: true
        schema:
          type: string
    get:
      summary: Get user
      operationId: getUser
      responses:
        "200":
          description: User details.
    delete:
      summary: Delete user
      operationId: deleteUser
      security: []
      responses:
        "204":
          description: Deleted.
  /profile:
    patch:
      summary: Update profile
      operationId: updateProfile
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
      responses:
        "200":
          description: Profile updated.
`;

const AUTH_DEMO_API_YAML = `openapi: 3.0.0
info:
  title: Broken Authentication Demo API
  version: "1.0"
  description: OpenAPI 3.0 specification demonstrating Broken Authentication differential testing.
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      description: HTTP Bearer token authentication
security:
  - BearerAuth: []
paths:
  /auth/secure/profile:
    get:
      summary: Retrieve protected user profile (Secure)
      description: Endpoint strictly enforces authentication; returns 401 Unauthorized when credentials are omitted.
      operationId: getSecureProfile
      responses:
        "200":
          description: Protected user profile successfully retrieved
        "401":
          description: Unauthorized - missing or invalid credentials
  /auth/vulnerable/profile:
    get:
      summary: Retrieve protected user profile (Vulnerable to Broken Authentication)
      description: OpenAPI declares authentication requirement, but implementation fails to verify credentials.
      operationId: getVulnerableProfile
      responses:
        "200":
          description: User profile retrieved
        "401":
          description: Unauthorized
`;

export const SAMPLE_SPECS: ApiSpec[] = [
  {
    id: 'spec-demo',
    title: 'Demo API (BOLA & BFLA Assessment)',
    version: '1.0.0',
    description: 'Verified testbed API with object parameters, administrative routines, and profile mutators.',
    baseUrl: 'http://127.0.0.1:8001',
    uploadedAt: 'Preloaded',
    format: 'yaml',
    rawContent: DEMO_API_YAML,
    endpoints: [
      {
        id: 'ep-demo-1',
        path: '/users',
        method: 'GET',
        summary: 'List users',
        authRequired: true,
        parameters: [{ name: 'limit', in: 'query', required: false, schemaType: 'integer' }],
        potentialRisks: ['Excessive Data Exposure'],
      },
      {
        id: 'ep-demo-2',
        path: '/users',
        method: 'POST',
        summary: 'Create a user',
        authRequired: true,
        parameters: [],
        potentialRisks: ['Mass Assignment'],
      },
      {
        id: 'ep-demo-3',
        path: '/users/{user_id}',
        method: 'GET',
        summary: 'Get user details by ID',
        authRequired: true,
        parameters: [{ name: 'user_id', in: 'path', required: true, schemaType: 'string' }],
        potentialRisks: ['BOLA / IDOR'],
      },
      {
        id: 'ep-demo-4',
        path: '/users/{user_id}',
        method: 'DELETE',
        summary: 'Delete user account',
        authRequired: false,
        parameters: [{ name: 'user_id', in: 'path', required: true, schemaType: 'string' }],
        potentialRisks: ['Broken Function Level Authorization (BFLA)'],
      },
      {
        id: 'ep-demo-5',
        path: '/profile',
        method: 'PATCH',
        summary: 'Update profile email',
        authRequired: true,
        parameters: [],
        potentialRisks: ['Mass Assignment'],
      },
    ],
  },
  {
    id: 'spec-auth-demo',
    title: 'Broken Authentication Demo API',
    version: '1.0.0',
    description: 'Testbed specification for Broken Authentication differential verification.',
    baseUrl: 'http://127.0.0.1:8001',
    uploadedAt: 'Preloaded',
    format: 'yaml',
    rawContent: AUTH_DEMO_API_YAML,
    endpoints: [
      {
        id: 'ep-auth-1',
        path: '/auth/secure/profile',
        method: 'GET',
        summary: 'Retrieve protected user profile (Secure)',
        authRequired: true,
        parameters: [],
        potentialRisks: ['Authentication Boundary'],
      },
      {
        id: 'ep-auth-2',
        path: '/auth/vulnerable/profile',
        method: 'GET',
        summary: 'Retrieve protected user profile (Vulnerable)',
        authRequired: true,
        parameters: [],
        potentialRisks: ['Broken Authentication (Missing Credentials)'],
      },
    ],
  },
];
