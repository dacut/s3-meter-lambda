#!/usr/bin/env python3
from base64 import b64decode, b64encode
from http import HTTPStatus
import logging
from os import environ, urandom
from sys import stderr

import boto3
from botocore.exceptions import ClientError as BotoClientError
from flask import (
    flash, Flask, make_response, redirect, render_template, request, session,
    url_for)
from markupsafe import escape as escape_html
from meterer import S3Meterer
from passlib.hash import pbkdf2_sha512
from redis import ConnectionPool, StrictRedis

logging.basicConfig(
    stream=stderr, level=logging.DEBUG,
    format=("%(asctime)s %(name)s %(filename)s:%(lineno)d [%(levelname)s]: "
            "%(message)s"))
log = logging.getLogger()
log.setLevel(logging.DEBUG)
logging.getLogger("botocore").setLevel(logging.INFO)
logging.getLogger("boto3").setLevel(logging.INFO)

# REDIS_ENDPOINT must point to the Redis cache we're using to store limit
# data and the like.
redis_endpoint = environ["REDIS_ENDPOINT"]
if ":" not in redis_endpoint:
    redis_endpoint += ":6379"

redis_host, redis_port = redis_endpoint.split(":")
redis_port = int(redis_port)
redis_pool = ConnectionPool(host=redis_host, port=redis_port)
redis = StrictRedis(connection_pool=redis_pool)

s3 = boto3.client("s3")
s3m = S3Meterer(cache=redis)

# How long URLs should be valid for.
expiration_timeout = int(environ.get("EXPIRATION_TIMEOUT", "30"))

app = Flask(__name__)
app.config["DEBUG"] = app.config["TESTING"] = True
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Secret key for the application session.
secret_key = environ.get("SECRET_KEY")
if secret_key is None:
    app.secret_key = urandom(18)
else:
    response = boto3.client("kms").decrypt(
        CiphertextBlob=b64decode(secret_key),
        EncryptionContext={
            "Application": "s3meter",
            "Usage": "Flask secret key",
        })

    app.secret_key = response["Plaintext"]

app.jinja_env.globals["len"] = len
app.jinja_env.globals["sorted"] = sorted

@app.template_global()
def get_allowed_buckets():
    return set(
        [el.decode("utf-8") for el in redis.smembers("ALLOWED_BUCKETS")])

@app.template_global()
def get_xsrf_token():
    if "xsrf_token" not in session:
        session["xsrf_token"] = b64encode(urandom(18)).decode("ascii")

    return session["xsrf_token"]

def xsrf_ok():
    form_xsrf = request.form.get("xsrf")
    session_xsrf = get_xsrf_token()
    return form_xsrf == session_xsrf

@app.route("/")
def get_root():
    return redirect(url_for("get_admin"))

@app.route("/admin")
def get_admin(code=HTTPStatus.OK):
    if "username" not in session:
        return make_response((render_template("login.html"), code, headers()))
    else:
        return make_response((render_template("admin.html"), code, headers()))

@app.route("/admin", methods=["POST"])
def post_admin():
    action = request.form.get("action")
    if "username" not in session and action != "login":
        return redirect(url_for("get_admin"), code=HTTPStatus.SEE_OTHER)

    if not xsrf_ok():
        flash("Cross-site request forgery attempt detected.", category="error")
        return get_admin(code=HTTPStatus.UNAUTHORIZED)

    if action in ("add-bucket", "remove-bucket"):
        bucket_name = request.form.get("bucket-name", "").strip()
        log.info("%s bucket_name=%r", action, bucket_name)
        if not bucket_name:
            flash("Bucket name cannot be empty.", category="error")
            return get_admin(code=HTTPStatus.BAD_REQUEST)

        if action == "add-bucket":
            redis.sadd("ALLOWED_BUCKETS", bucket_name)
            flash("Bucket %s added" % escape_html(bucket_name), category="info")
        else:
            redis.srem("ALLOWED_BUCKETS", bucket_name)
            flash("Bucket %s removed" % escape_html(bucket_name),
                  category="info")

        return get_admin()
    elif action == "login":
        credentials = environ.get("ADMIN_CREDENTIALS")
        if "username" in session:
            del session["username"]

        if not credentials:
            flash("This site cannot be administered.", category="error")
            return get_admin(code=HTTPStatus.FORBIDDEN)

        password = request.form.get("password", "")
        if pbkdf2_sha512.verify(password, credentials):
            session["username"] = "Admin"
            return redirect(url_for("get_admin"))

        flash("Invalid password.", category="error")
        log.info("Invalid password submitted")
        return get_admin(code=HTTPStatus.UNAUTHORIZED)
    else:
        flash("Unknown action requested", category="error")
        return get_admin(code=HTTPStatus.BAD_REQUEST)

@app.route("/admin/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("get_admin"))

@app.route("/admin/bucket/<bucket>", methods=["GET", "HEAD"])
def get_bucket(bucket, code=HTTPStatus.OK):
    return make_response((
        render_template("bucket.html", bucket=bucket,
                        limits=s3m.get_limits_for_pool(bucket)),
        code,
        headers()))

@app.route("/admin/bucket/<bucket>", methods=["POST"])
def post_bucket(bucket, code=HTTPStatus.OK):
    action = request.form.get("action")
    if "username" not in session and action != "login":
        return redirect(url_for("get_admin"), code=HTTPStatus.SEE_OTHER)

    if not xsrf_ok():
        flash("Cross-site request forgery attempt detected.", category="error")
        return get_bucket(bucket, code=HTTPStatus.UNAUTHORIZED)

    if action == "set-bucket-limits":
        log.info("set-bucket-limits bucket_name=%r", bucket)

        if not bucket:
            flash("Empty bucket specified.", category="error")
            return get_bucket(bucket, HTTPStatus.BAD_REQUEST)

        errors = False
        limits = {}

        for period in ["hour", "day", "week", "month", "year"]:
            period_limit = request.form.get(period + "-mb")

            if not period_limit:
                limits[period] = None
            else:
                try:
                    period_limit = float(period_limit)
                    if period_limit < 0:
                        raise ValueError()

                    limits[period] = int(period_limit * 1e6)
                except ValueError:
                    flash("Invalid value for %s limit: %r" %
                          (period, escape_html(str(period_limit))),
                          category="error")
                    errors = True

        if errors:
            return get_bucket(bucket, HTTPStatus.BAD_REQUEST)

        s3m.set_limits_for_pool(bucket, **limits)
        return get_bucket(bucket)
    else:
        flash("Unknown action requested", category="error")
        return get_bucket(bucket, code=HTTPStatus.BAD_REQUEST)


@app.route("/<bucket>/<path:key>", methods=["GET", "HEAD"])
def get_s3_object(bucket, key):
    if bucket not in get_allowed_buckets():
        return make_response((
            "<Error><Code>AccessDenied</Code>"
            "<Message>Unknown bucket requested</Message>"
            "</Error>",
            HTTPStatus.FORBIDDEN,
            headers(ContentType="application/xml")))

    s3_path = "s3://%s/%s" % (bucket, key)
    try:
        if not s3m.allow_resource_access(s3_path):
            log.info("Capacity exceeded for %s", s3_path)
            return make_response((
                "<Error><Code>SlowDown</Code>"
                "<Message>Access capacity for bucket exceeded</Message>"
                "</Error>",
                HTTPStatus.SERVICE_UNAVAILABLE,
                headers(ContentType="application/xml")))
    except BotoClientError as e:
        error_code = int(e.response.get("Error").get("Code", "0"))
        if error_code == HTTPStatus.NOT_FOUND:
            return make_response((
                "<Error><Code>AccessDenied</Code>"
                "<Message>Access Denied</Message></Error>",
                HTTPStatus.FORBIDDEN,
                headers(ContentType="application/xml"),
            ))

        raise

    url = s3.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expiration_timeout, HttpMethod=http_method)

    log.info("Redirecting %r to %r", path, url)
    return redirect(url, code=int(HTTPStatus.TEMPORARY_REDIRECT))

def headers(**kw):
    """
    Return a dictionary of headers for this request.
    """
    result = {
        "Server": "S3Meterer",
    }
    if "ContentType" in kw:
        result["Content-Type"] = kw.pop("ContentType")

    result.update(kw)
    return result
