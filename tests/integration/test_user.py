# ======================================================================================
# tests/integration/test_user.py
# ======================================================================================
# Purpose: Demonstrate user model interactions with the database using pytest fixtures.
#          Relies on 'conftest.py' for database session management and test isolation.
# ======================================================================================


import uuid
from pydantic import ValidationError
import pytest
import logging
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.auth import jwt
from jose import jwt as jose_jwt
from app.models.user import User
from app.schemas.user import PasswordUpdate, UserCreate
from tests.conftest import create_fake_user, managed_db_session

# Use the logger configured in conftest.py
logger = logging.getLogger(__name__)

# ======================================================================================
# Basic Connection & Session Tests
# ======================================================================================

def test_database_connection(db_session):
    """
    Verify that the database connection is working.
    
    Uses the db_session fixture from conftest.py, which truncates tables after each test.
    """
    result = db_session.execute(text("SELECT 1"))
    assert result.scalar() == 1
    logger.info("Database connection test passed")


def test_managed_session():
    """
    Test the managed_db_session context manager for one-off queries and rollbacks.
    Demonstrates how a manual session context can work alongside the fixture-based approach.
    """
    with managed_db_session() as session:
        # Simple query
        session.execute(text("SELECT 1"))
        
        # Generate an error to trigger rollback
        try:
            session.execute(text("SELECT * FROM nonexistent_table"))
        except Exception as e:
            assert "nonexistent_table" in str(e)

# ======================================================================================
# Session Handling & Partial Commits
# ======================================================================================
def test_session_handling(db_session):
    """
    Demonstrate partial commits:
      - user1 is committed successfully.
      - user2 fails (due to duplicate email), triggering a rollback.
      - user3 is committed successfully.
      - The final user count should be the initial count plus two (user1 and user3).
    """
    # Use the current user count as our baseline.
    initial_count = db_session.query(User).count()
    logger.info(f"Initial user count before test_session_handling: {initial_count}")

    # Create and commit user1.
    user1 = User(
        first_name="User",
        last_name="One",
        email="user1@example.com",
        username="user1",
        password="hashed_password"
    )
    db_session.add(user1)
    db_session.commit()

    # Attempt to create user2 with a duplicate email (should fail).
    user2 = User(
        first_name="User",
        last_name="Two",
        email="user1@example.com",  # Duplicate email
        username="user2",
        password="hashed_password"
    )
    db_session.add(user2)
    try:
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        logger.info(f"Expected failure on duplicate user2: {e}")

    # Create and commit user3 with unique email/username.
    user3 = User(
        first_name="User",
        last_name="Three",
        email="user3@example.com",
        username="user3",
        password="hashed_password"
    )
    db_session.add(user3)
    db_session.commit()

    # Verify that only two additional users have been added.
    final_count = db_session.query(User).count()
    expected_final = initial_count + 2
    assert final_count == expected_final, (
        f"Expected {expected_final} users after test, found {final_count}"
    )

# ======================================================================================
# User Creation Tests
# ======================================================================================

def test_create_user_with_faker(db_session):
    """
    Create a single user using Faker-generated data and verify it was saved.
    """
    user_data = create_fake_user()
    logger.info(f"Creating user with data: {user_data}")
    
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)  # Refresh populates fields like user.id
    
    assert user.id is not None
    assert user.email == user_data["email"]
    logger.info(f"Successfully created user with ID: {user.id}")


def test_create_multiple_users(db_session):
    """
    Create multiple users in a loop and verify they are all saved.
    """
    users = []
    for _ in range(3):
        user_data = create_fake_user()
        user = User(**user_data)
        users.append(user)
        db_session.add(user)
    
    db_session.commit()
    assert len(users) == 3
    logger.info(f"Successfully created {len(users)} users")

def test_user_create_passwords_do_not_match():
    user= create_fake_user()
    user["confirm_password"] = "Different123!"

    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**user)

    error_message = str(exc_info.value).lower()
    assert "passwords do not match" in error_message

def test_user_create_passwords_match():
    user= create_fake_user()
    user["password"] = "Same12345!"
    user["confirm_password"] = "Same12345!"

    UserCreate(**user)

    assert user["password"] == user["confirm_password"]

def test_user_create_passwords_strength_upper():
    user= create_fake_user()
    user["password"] = "same12345!"
    user["confirm_password"] = "same12345!"

    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**user)

    error_message = str(exc_info.value).lower()
    assert "password must contain at least one uppercase letter" in error_message

def test_user_create_passwords_strength_lower():
    user= create_fake_user()
    user["password"] = "SAME12345!"
    user["confirm_password"] = "SAME12345!"

    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**user)

    error_message = str(exc_info.value).lower()
    assert "password must contain at least one lowercase letter" in error_message

def test_user_create_passwords_strength_digit():
    user= create_fake_user()
    user["password"] = "Samepassword!"
    user["confirm_password"] = "Samepassword!"

    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**user)

    error_message = str(exc_info.value).lower()
    assert "password must contain at least one digit" in error_message

def test_user_create_passwords_strength_special():
    user= create_fake_user()
    user["password"] = "Same1234"
    user["confirm_password"] = "Same1234"

    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**user)

    error_message = str(exc_info.value).lower()
    assert "password must contain at least one special character" in error_message




# ======================================================================================
# Query Tests
# ======================================================================================

def test_query_methods(db_session, seed_users):
    """
    Illustrate various query methods using seeded users.
    
    - Counting all users
    - Filtering by email
    - Ordering by email
    """
    user_count = db_session.query(User).count()
    assert user_count >= len(seed_users), "The user table should have at least the seeded users"
    
    first_user = seed_users[0]
    found = db_session.query(User).filter_by(email=first_user.email).first()
    assert found is not None, "Should find the seeded user by email"
    
    users_by_email = db_session.query(User).order_by(User.email).all()
    assert len(users_by_email) >= len(seed_users), "Query should return at least the seeded users"

# ======================================================================================
# Transaction / Rollback Tests
# ======================================================================================

def test_transaction_rollback(db_session):
    """
    Demonstrate how a partial transaction fails and triggers rollback.
    - We add a user and force an error
    - We catch the error and rollback
    - Verify the user was not committed
    """
    initial_count = db_session.query(User).count()
    
    try:
        user_data = create_fake_user()
        user = User(**user_data)
        db_session.add(user)
        # Force an error to trigger rollback
        db_session.execute(text("SELECT * FROM nonexistent_table"))
        db_session.commit()
    except Exception:
        db_session.rollback()
    
    final_count = db_session.query(User).count()
    assert final_count == initial_count, "The new user should not have been committed"

# ======================================================================================
# Update Tests
# ======================================================================================

def test_update_with_refresh(db_session, test_user):
    """
    Update a user's email and refresh the session to see updated fields.
    """
    original_email = test_user.email
    original_update_time = test_user.updated_at
    
    new_email = f"new_{original_email}"
    test_user.email = new_email
    db_session.commit()
    db_session.refresh(test_user)  # Refresh to populate any updated_at or other fields
    
    assert test_user.email == new_email, "Email should have been updated"
    assert test_user.updated_at > original_update_time, "Updated time should be newer"
    logger.info(f"Successfully updated user {test_user.id}")

def test_user_update_passwords_do_not_match():
    data = {"current_password":"OldPassword123!",
            "new_password": "NewPassword123!",
             "confirm_new_password": "Different123!"}

    with pytest.raises(ValidationError) as exc_info:
        PasswordUpdate(**data)

    error_message = str(exc_info.value).lower()
    assert "new password and confirmation do not match" in error_message

def test_user_update_passwords_old_same_new():
    data = {"current_password":"OldPassword123!",
            "new_password": "OldPassword123!",
             "confirm_new_password": "OldPassword123!"}

    with pytest.raises(ValidationError) as exc_info:
        PasswordUpdate(**data)

    error_message = str(exc_info.value).lower()
    assert "new password must be different from current password" in error_message

def test_user_update_passwords_match():
    data = {"current_password":"OldPassword123!",
            "new_password": "NewPassword123!",
             "confirm_new_password": "NewPassword123!"}

    update = PasswordUpdate(**data)

    assert update.new_password == update.confirm_new_password
    assert update.current_password != update.new_password


def test_user_update_method_updates_fields_and_timestamp(db_session):
    user_data = create_fake_user()

    user = User(
        first_name=user_data["first_name"],
        last_name=user_data["last_name"],
        email=user_data["email"],
        username=user_data["username"],
        password=user_data["password"],  # already hashed in tests
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    old_updated_at = user.updated_at

    # Update with new unique values
    new_email = f"updated_{user_data['email']}"
    returned = user.update(
        first_name="Updated",
        email=new_email,
    )

    db_session.commit()
    db_session.refresh(user)

    assert returned is user
    assert user.first_name == "Updated"
    assert user.email == new_email
    assert user.updated_at > old_updated_at


# ======================================================================================
# Bulk Operation Tests
# ======================================================================================

@pytest.mark.slow
def test_bulk_operations(db_session):
    """
    Test bulk inserting multiple users at once (marked slow).
    Use --run-slow to enable this test.
    """
    users_data = [create_fake_user() for _ in range(10)]
    users = [User(**data) for data in users_data]
    db_session.bulk_save_objects(users)
    db_session.commit()
    
    count = db_session.query(User).count()
    assert count >= 10, "At least 10 users should now be in the database"
    logger.info(f"Successfully performed bulk operation with {len(users)} users")

# ======================================================================================
# Uniqueness Constraint Tests
# ======================================================================================

def test_unique_email_constraint(db_session):
    """
    Create two users with the same email and expect an IntegrityError.
    """
    first_user_data = create_fake_user()
    first_user = User(**first_user_data)
    db_session.add(first_user)
    db_session.commit()
    
    second_user_data = create_fake_user()
    second_user_data["email"] = first_user_data["email"]  # Force a duplicate email
    second_user = User(**second_user_data)
    db_session.add(second_user)
    
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_username_constraint(db_session):
    """
    Create two users with the same username and expect an IntegrityError.
    """
    first_user_data = create_fake_user()
    first_user = User(**first_user_data)
    db_session.add(first_user)
    db_session.commit()
    
    second_user_data = create_fake_user()
    second_user_data["username"] = first_user_data["username"]  # Force a duplicate username
    second_user = User(**second_user_data)
    db_session.add(second_user)
    
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

# ======================================================================================
# Persistence after Constraint Violation
# ======================================================================================

def test_user_persistence_after_constraint(db_session):
    """
    - Create and commit a valid user
    - Attempt to create a duplicate user (same email) -> fails
    - Confirm the original user still exists
    """
    initial_user_data = {
        "first_name": "First",
        "last_name": "User",
        "email": "first@example.com",
        "username": "firstuser",
        "password": "password123"
    }
    initial_user = User(**initial_user_data)
    db_session.add(initial_user)
    db_session.commit()
    saved_id = initial_user.id
    
    try:
        duplicate_user = User(
            first_name="Second",
            last_name="User",
            email="first@example.com",  # Duplicate
            username="seconduser",
            password="password456"
        )
        db_session.add(duplicate_user)
        db_session.commit()
        assert False, "Should have raised IntegrityError"
    except IntegrityError:
        db_session.rollback()
    
    found_user = db_session.query(User).filter_by(id=saved_id).first()
    assert found_user is not None, "Original user should exist"
    assert found_user.id == saved_id, "Should find original user by ID"
    assert found_user.email == "first@example.com", "Email should be unchanged"
    assert found_user.username == "firstuser", "Username should be unchanged"

# ======================================================================================
# Error Handling Test
# ======================================================================================

def test_error_handling():
    """
    Verify that a manual managed_db_session can capture and log invalid SQL errors.
    """
    with pytest.raises(Exception) as exc_info:
        with managed_db_session() as session:
            session.execute(text("INVALID SQL"))
    assert "INVALID SQL" in str(exc_info.value)

# ======================================================================================
# Hashed Passwords Tests
# ======================================================================================

def test_user_init_with_hashed_password(db_session):
    user = User(
        first_name="Test",
        last_name="User",
        email="test@example.com",
        username="testuser",
        hashed_password="hashed-secret",  
    )

    db_session.add(user)
    db_session.commit()

    assert user.password == "hashed-secret"

def test_user_init_without_hashed_password(db_session):
    user = User(
        first_name="Test",
        last_name="User",
        email="test2@example.com",
        username="testuser2",
        password="already-hashed",
    )

    db_session.add(user)
    db_session.commit()

    assert user.password == "already-hashed"

def test_user_hashed_password_property(db_session):
    user_data = create_fake_user()

    user = User(
        first_name=user_data["first_name"],
        last_name=user_data["last_name"],
        email=user_data["email"],
        username=user_data["username"],
        password=user_data["password"],  # already "hashed" for tests
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.hashed_password == user.password

# ======================================================================================
# Authenticate User Tests
# ======================================================================================

def test_authenticate_user_not_found(db_session):
    result = User.authenticate(
        db=db_session,
        username_or_email="doesnotexist",
        password="Whatever123!",
    )

    assert result is None

def test_authenticate_wrong_password(db_session):
    user_data = create_fake_user()

    hashed_pw = jwt.get_password_hash(user_data["password"])

    user = User(
        first_name=user_data["first_name"],
        last_name=user_data["last_name"],
        email=user_data["email"],
        username=user_data["username"],
        password=hashed_pw,  # hashed
    )

    db_session.add(user)
    db_session.commit()

    result = User.authenticate(
        db=db_session,
        username_or_email=user_data["username"],
        password="WrongPassword123!",
    )

    assert result is None


def test_authenticate_success(db_session):
    user_data = create_fake_user()

    hashed_pw = jwt.get_password_hash(user_data["password"])

    user = User(
        first_name=user_data["first_name"],
        last_name=user_data["last_name"],
        email=user_data["email"],
        username=user_data["username"],
        password=hashed_pw,
    )

    db_session.add(user)
    db_session.commit()

    result = User.authenticate(
        db=db_session,
        username_or_email=user_data["email"],
        password=user_data["password"],  # plain text input
    )

    assert result is not None

# ======================================================================================
# JWT Token Tests
# ======================================================================================

def test_verify_token_invalid_token():
    result = User.verify_token("this.is.not.a.jwt")
    assert result is None

def test_verify_token_missing_sub():
    token = jose_jwt.encode(
        {"foo": "bar"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    result = User.verify_token(token)
    assert result is None

def test_verify_token_invalid_uuid_sub():
    token = jose_jwt.encode(
        {"sub": "not-a-uuid"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    result = User.verify_token(token)
    assert result is None

def test_verify_token_valid():
    user_id = uuid.uuid4()

    token = jose_jwt.encode(
        {"sub": str(user_id)},
        settings.JWT_SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    result = User.verify_token(token)

    assert result == user_id
