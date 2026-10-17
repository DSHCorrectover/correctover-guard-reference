"""Destructive-sql rule: catastrophic DDL/DML is denied; safe SQL is allowed."""

from correctover_guard_ref.rules import inspect_tool_arguments


def deny_id(args):
    return inspect_tool_arguments(args)


ATTACKS = [
    "DROP TABLE users",
    "drop table users",
    "DROP TABLE IF EXISTS orders",
    "DROP DATABASE production",
    "DROP SCHEMA public CASCADE",
    "TRUNCATE TABLE accounts",
    "truncate table accounts",
    "DELETE FROM users",
    "delete from users",
    "UPDATE users SET role='admin'",
]

SAFE = [
    "SELECT * FROM users WHERE id = 1",
    "DELETE FROM users WHERE id = 7",
    "UPDATE users SET name='a' WHERE id = 2",
    "INSERT INTO users (name) VALUES ('a')",
    # prose under a non-execution key is not even execution-scanned for SQL
]


def test_attacks_denied_under_execution_key():
    for sql in ATTACKS:
        assert deny_id({"statement": sql}) == "destructive-sql", sql


def test_safe_sql_allowed():
    for sql in SAFE:
        assert deny_id({"statement": sql}) is None, sql


def test_non_execution_key_not_scoped():
    # a description field mentioning DROP TABLE must not trip an execution rule
    assert deny_id({"description": "we discussed DROP TABLE semantics today"}) is None


def test_drop_also_blocked_in_command_key():
    assert deny_id({"command": "psql -c 'DROP TABLE users'"}) == "destructive-sql"
