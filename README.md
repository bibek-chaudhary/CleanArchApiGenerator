# 🚀 Clean Architecture API Boilerplate Generator

> ⚡ Generate production-ready ASP.NET Core Web APIs in seconds — powered by Clean Architecture, Identity, JWT, EF Core, and SQL Server.

A local web-based generator that scaffolds an **enterprise-grade backend solution** following industry best practices.
Designed for developers who want to eliminate repetitive setup and start building features immediately.

---

## 🎯 Why This Project Exists

Every new backend project starts with the same tedious tasks:

* Creating solution structure
* Configuring authentication
* Setting up database & migrations
* Wiring dependencies
* Adding validation & error handling

This tool automates all of that.

👉 **One click → Fully working production-ready API**

---

## ✨ Key Highlights

✅ Clean Architecture implementation
✅ Controller-based ASP.NET Core Web API
✅ ASP.NET Core Identity (EF-based)
✅ JWT Authentication & Role Authorization
✅ SQL Server + EF Core configured
✅ Default Admin seeding
✅ Global Exception Handling
✅ FluentValidation integration
✅ Standardized API response system
✅ Swagger with JWT support

---

## 🧱 Generated Architecture

```
ProjectName/
 ├── ProjectName.Domain         → Core business entities
 ├── ProjectName.Application    → Use cases & interfaces
 ├── ProjectName.Infrastructure → Data access & Identity
 └── ProjectName.API            → Presentation layer
```

✔ Follows Clean Architecture principles
✔ Enforces separation of concerns
✔ Scalable for enterprise applications

---

## 🔐 Authentication & Authorization

* ASP.NET Core Identity integration
* JWT-based stateless authentication
* Role-based authorization
* Secure password policies
* Ready for SPA & mobile clients

### 👤 Default Admin Account

Automatically created on first run:

```
Email: admin@example.com
Password: Admin@123
```

---

## 🛡️ Production-Grade API Features

### ✔ Global Exception Handling

Centralized middleware for consistent error responses.

### ✔ FluentValidation

Request validation using clean, testable rules.

### ✔ Standardized API Responses

Consistent structure across all endpoints:

```json
{
  "success": true,
  "message": "Operation successful",
  "data": { }
}
```

### ✔ Swagger with JWT Support

Interactive API documentation with secure testing.

---

## 🗄️ Database & Persistence

* Entity Framework Core
* SQL Server default provider
* Code-first migrations
* Identity tables preconfigured

---

## 🖥️ Generator Capabilities

✔ Runs locally (no cloud dependency)
✔ Generates full solution structure
✔ Restores NuGet packages
✔ Builds automatically
✔ Outputs ready-to-run project

Generated projects are saved to:

```
backend/GeneratedProjects/{ProjectName}
```

---

## ⚙️ Prerequisites

Ensure the following are installed:

* .NET SDK 8+
* SQL Server (LocalDB or full)
* Visual Studio / VS Code
* Git (optional)

---

## ▶️ Running the Generator

Navigate to the generator API project:

```bash
cd backend/CleanArchApiGenerator.API
dotnet run
```

Open Swagger UI:

```
https://localhost:{port}/swagger
```

Use the endpoint to generate a new API project.

---

## ▶️ Running a Generated API

Navigate to your generated project:

```bash
cd backend/GeneratedProjects/YourProjectName/YourProjectName.API
```

Apply database migrations:

```bash
dotnet ef database update \
  --project ../YourProjectName.Infrastructure \
  --startup-project .
```

Run the API:

```bash
dotnet run
```

Open Swagger:

```
https://localhost:{port}/
```

---

## 🔑 Testing Authentication

1. Call the login endpoint
2. Copy the JWT token
3. Click **Authorize** in Swagger
4. Enter:

```
Bearer YOUR_TOKEN_HERE
```

---

## 📦 Technology Stack

### Backend

* ASP.NET Core Web API
* Clean Architecture
* Entity Framework Core
* SQL Server
* ASP.NET Core Identity
* JWT Authentication

### Supporting Libraries

* FluentValidation
* Swashbuckle (Swagger/OpenAPI)

---

## 🚀 Real-World Use Cases

This boilerplate is suitable for:

✔ SaaS backends
✔ Enterprise applications
✔ Microservices foundations
✔ Startup MVPs
✔ Internal company tools
✔ Learning Clean Architecture
✔ Rapid prototyping

---

## 🧪 What Makes This Portfolio-Grade

This project demonstrates:

* Architectural design skills
* Security implementation
* Enterprise backend patterns
* Production-ready coding practices
* Automation mindset
* Full-stack readiness

---

## 🚧 Potential Future Enhancements

* Refresh token authentication
* Structured logging (Serilog)
* API versioning
* Pagination utilities
* Docker support
* CI/CD pipelines
* Multi-tenant support

---

## 🤝 Contributing

Contributions and suggestions are welcome.

---

## ⭐ Support

If this project helped you or inspired you:

👉 Give it a star ⭐ on GitHub

---

## 👨‍💻 Author

Built as a professional backend starter toolkit for modern .NET development.
