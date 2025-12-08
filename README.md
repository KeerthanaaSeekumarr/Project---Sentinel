# Sentinel-X Defense Platform

Sentinel-X is a unified, next-generation network traffic analysis and simulated threat detection platform. Designed for speed and clarity in forensic investigation and real-time monitoring, it utilizes custom multi-threading to simulate live network traffic and advanced threat signatures.

## Features

- **Real-time Traffic Monitoring:** Continuously simulates and displays network packets, including source/destination IP, protocol, and length.
- **Threat Detection:** Identifies and flags simulated security events like **SQL Injection**, **XSS Attempts**, **Buffer Overflow**, and **Zero-Day Exploits** with severity levels (Low, Medium, High, Critical).
- **IP Range Analysis:** Allows targeted simulation of IP Detail Record (IPDR) data for a specified IP range.
- **Data Export:** Export all current buffered packets to downloadable JSON or CSV files.
- **Traffic Control:** API endpoints to start, stop, and clear the simulated traffic generator.
- **PostgreSQL Storage:** Persistent packet storage with PostgreSQL database support.
- **Decoupled Architecture:** Clean separation between REST API, business logic, and data persistence layers.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌────────────┐
│  REST API   │────>│   Service   │────>│ PacketRepository │────>│ PostgreSQL │
│  (app.py)   │     │    Layer    │     │   (Abstract)     │     │            │
└─────────────┘     └─────────────┘     └──────────────────┘     └────────────┘
                          │
                          v
                   ┌─────────────┐
                   │TrafficEngine│
                   │ (Generator) │
                   └─────────────┘
```

## Prerequisites

- **Python 3.9+**
- **Docker** and **Docker Compose** (for PostgreSQL)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/Project-Sentinel.git
cd Project-Sentinel
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Linux/macOS
# .\venv\Scripts\activate # On Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

Copy the example environment file and adjust as needed:

```bash
cp env.example .env
```

Default configuration works with the Docker PostgreSQL setup.

### 5. Start PostgreSQL with Docker

```bash
docker-compose up -d
```

This starts a PostgreSQL 15 container with:

- **Host:** localhost
- **Port:** 5432
- **Database:** sentinel_db
- **User:** sentinel
- **Password:** sentinel_pass

Verify it's running:

```bash
docker-compose ps
```

### 6. Run Database Migrations

```bash
python migrate.py up
```

Check migration status:

```bash
python migrate.py status
```

### 7. Generate SSL Certificates (Optional)

For HTTPS support:

```bash
python gen_certs.py
```

### 8. Start the Application

```bash
python app.py
```

The application will:

1. Connect to PostgreSQL (or fall back to in-memory storage if unavailable)
2. Start the traffic generator automatically
3. Serve the web interface at http://localhost:5000

## Database Management

### Migration Commands

```bash
# Run all pending migrations
python migrate.py up

# Check migration status
python migrate.py status

# Reset database (WARNING: deletes all data)
python migrate.py reset
```

### Migration Files

Migrations are stored in the `migrations/` folder:

```
migrations/
├── 001_create_packets_table.sql
└── 002_add_indexes.sql
```

To add a new migration, create a file with the next sequence number (e.g., `003_add_new_column.sql`).

### Docker Commands

```bash
# Start PostgreSQL
docker-compose up -d

# Stop PostgreSQL
docker-compose down

# Stop and remove volumes (deletes all data)
docker-compose down -v

# View logs
docker-compose logs -f postgres

# Connect to PostgreSQL CLI
docker exec -it sentinel-postgres psql -U sentinel -d sentinel_db
```

## API Endpoints

### Traffic Control

| Method | Endpoint            | Description                                            |
| ------ | ------------------- | ------------------------------------------------------ |
| POST   | `/api/control`      | Control traffic generator (`action`: start/stop/clear) |
| GET    | `/api/status`       | Get engine status                                      |
| GET    | `/api/packets`      | Get all packets (optional `?limit=N`)                  |
| GET    | `/api/packets/<id>` | Get packet by ID                                       |
| GET    | `/api/statistics`   | Get packet statistics                                  |

### IP Range Processing

| Method | Endpoint                | Description                             |
| ------ | ----------------------- | --------------------------------------- |
| POST   | `/api/process_ip_range` | Process IP range (`start_ip`, `end_ip`) |

### Data Export

| Method | Endpoint                  | Description            |
| ------ | ------------------------- | ---------------------- |
| GET    | `/api/export_packets`     | Export packets as JSON |
| GET    | `/api/export_packets_csv` | Export packets as CSV  |

### Health Check

| Method | Endpoint      | Description      |
| ------ | ------------- | ---------------- |
| GET    | `/api/health` | API health check |

## Configuration

Environment variables (set in `.env` file):

| Variable                   | Default       | Description                      |
| -------------------------- | ------------- | -------------------------------- |
| `DATABASE_HOST`            | localhost     | PostgreSQL host                  |
| `DATABASE_PORT`            | 5432          | PostgreSQL port                  |
| `DATABASE_NAME`            | sentinel_db   | Database name                    |
| `DATABASE_USER`            | sentinel      | Database user                    |
| `DATABASE_PASSWORD`        | sentinel_pass | Database password                |
| `DATABASE_MIN_CONNECTIONS` | 1             | Min pool connections             |
| `DATABASE_MAX_CONNECTIONS` | 10            | Max pool connections             |
| `FLASK_HOST`               | 0.0.0.0       | Flask bind host                  |
| `FLASK_PORT`               | 5000          | Flask bind port                  |
| `DEBUG`                    | False         | Enable debug mode                |
| `PACKET_BUFFER_LIMIT`      | 500           | Max packets (in-memory fallback) |

## Project Structure

```
Project-Sentinel/
├── app.py                 # Flask REST API
├── config.py              # Environment configuration
├── database.py            # PostgreSQL connection pool
├── repository.py          # Data access layer
├── services.py            # Business logic layer
├── traffic_engine.py      # Traffic generator
├── migrate.py             # Migration runner
├── docker-compose.yml     # PostgreSQL container
├── requirements.txt       # Python dependencies
├── env.example            # Environment template
├── gen_certs.py           # SSL certificate generator
├── migrations/
│   ├── 001_create_packets_table.sql
│   └── 002_add_indexes.sql
├── certs/
│   └── .gitkeep
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
└── templates/
    ├── base.html
    ├── about.html
    ├── dashboard.html
    ├── monitor.html
    └── processor.html
```

## Fallback Mode

If PostgreSQL is unavailable, the application automatically falls back to an in-memory buffer. This is useful for:

- Development without Docker
- Quick testing
- Environments where PostgreSQL isn't available

Note: In-memory mode does not persist data between restarts.

## Troubleshooting

### Database Connection Issues

1. Ensure Docker is running: `docker-compose ps`
2. Check PostgreSQL logs: `docker-compose logs postgres`
3. Verify environment variables in `.env`
4. Test connection: `docker exec -it sentinel-postgres psql -U sentinel -d sentinel_db`

### Migration Issues

1. Check migration status: `python migrate.py status`
2. Verify SQL syntax in migration files
3. Reset if needed: `python migrate.py reset`

### Port Conflicts

If port 5432 is in use:

1. Stop other PostgreSQL instances
2. Or change port in `docker-compose.yml` and `.env`

## License

MIT License
