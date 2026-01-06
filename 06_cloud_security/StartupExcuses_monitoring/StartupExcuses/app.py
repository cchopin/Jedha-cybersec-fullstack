import os
from datetime import datetime

import boto3
import dotenv
import psycopg2
from flask import Flask, redirect, render_template, request, url_for

dotenv.load_dotenv()

app = Flask(__name__)

# Configuration CloudWatch
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
boto3.setup_default_session(region_name=AWS_REGION)
cloudwatch = boto3.client("cloudwatch")


def send_custom_metric(metric_name, value, unit="Count"):
    """Envoie une metrique custom a CloudWatch."""
    try:
        cloudwatch.put_metric_data(
            Namespace="StartupExcuses/Application",
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": value,
                    "Unit": unit,
                    "Timestamp": datetime.utcnow(),
                }
            ],
        )
    except Exception as e:
        # Log l'erreur mais ne bloque pas l'application
        print(f"Erreur envoi metrique CloudWatch: {e}")


# Database connection
def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        database=os.getenv("DB_NAME", "startup_excuses"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "password"),
        port=os.getenv("DB_PORT", "5432"),
    )


def init_db():
    try:
        print("Checking/creating database...")

        # First, connect to default postgres database to create our database
        default_conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            database="postgres",  # Connect to default database
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "password"),
            port=os.getenv("DB_PORT", "5432"),
        )
        default_conn.autocommit = True

        with default_conn.cursor() as cur:
            # Check if our database exists
            cur.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                [os.getenv("DB_NAME", "startup_excuses")],
            )
            exists = cur.fetchone()

            if not exists:
                cur.execute(
                    f'CREATE DATABASE "{os.getenv("DB_NAME", "startup_excuses")}"'
                )
                print(f"Database {os.getenv('DB_NAME', 'startup_excuses')} created")

        default_conn.close()

        # Now connect to our application database and create tables
        print("Initializing tables...")
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS excuses (
                        id SERIAL PRIMARY KEY,
                        excuse TEXT NOT NULL,
                        votes INTEGER DEFAULT 0,
                        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )
                print("Database initialized")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise e


@app.route("/")
def home():
    send_custom_metric("PageViews", 1)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, excuse, votes FROM excuses ORDER BY votes DESC LIMIT 10"
            )
            top_excuses = cur.fetchall()
    return render_template("index.html", excuses=top_excuses)


@app.route("/submit", methods=["POST"])
def submit_excuse():
    send_custom_metric("ExcuseSubmissions", 1)
    excuse = request.form["excuse"]
    if excuse.strip():
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO excuses (excuse) VALUES (%s)", (excuse,))
    return redirect(url_for("home"))


@app.route("/vote/<int:excuse_id>")
def vote(excuse_id):
    send_custom_metric("Votes", 1)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE excuses SET votes = votes + 1 WHERE id = %s", (excuse_id,)
            )
    return redirect(url_for("home"))


@app.route("/health")
def health():
    return {"status": "healthy", "app": "StartupExcuses", "monitoring": "enabled"}, 200


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
