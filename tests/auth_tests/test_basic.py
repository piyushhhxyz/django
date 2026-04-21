from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
    get_user,
    get_user_model,
    login,
)
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError
from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.utils import translation

from .models import CustomUser


class BasicTestCase(TestCase):
    def test_user(self):
        "Users can be created and can set their password"
        u = User.objects.create_user("testuser", "test@example.com", "testpw")
        self.assertTrue(u.has_usable_password())
        self.assertFalse(u.check_password("bad"))
        self.assertTrue(u.check_password("testpw"))

        # Check we can manually set an unusable password
        u.set_unusable_password()
        u.save()
        self.assertFalse(u.check_password("testpw"))
        self.assertFalse(u.has_usable_password())
        u.set_password("testpw")
        self.assertTrue(u.check_password("testpw"))
        u.set_password(None)
        self.assertFalse(u.has_usable_password())

        # Check username getter
        self.assertEqual(u.get_username(), "testuser")

        # Check authentication/permissions
        self.assertFalse(u.is_anonymous)
        self.assertTrue(u.is_authenticated)
        self.assertFalse(u.is_staff)
        self.assertTrue(u.is_active)
        self.assertFalse(u.is_superuser)

        # Check API-based user creation with no password
        u2 = User.objects.create_user("testuser2", "test2@example.com")
        self.assertFalse(u2.has_usable_password())

    def test_unicode_username(self):
        User.objects.create_user("jörg")
        User.objects.create_user("Григорий")
        # Two equivalent Unicode normalized usernames are duplicates.
        omega_username = "iamtheΩ"  # U+03A9 GREEK CAPITAL LETTER OMEGA
        ohm_username = "iamtheΩ"  # U+2126 OHM SIGN
        User.objects.create_user(ohm_username)
        with self.assertRaises(IntegrityError):
            User.objects.create_user(omega_username)

    def test_user_no_email(self):
        "Users can be created without an email"
        cases = [
            {},
            {"email": ""},
            {"email": None},
        ]
        for i, kwargs in enumerate(cases):
            with self.subTest(**kwargs):
                u = User.objects.create_user("testuser{}".format(i), **kwargs)
                self.assertEqual(u.email, "")

    def test_superuser(self):
        "Check the creation and properties of a superuser"
        super = User.objects.create_superuser("super", "super@example.com", "super")
        self.assertTrue(super.is_superuser)
        self.assertTrue(super.is_active)
        self.assertTrue(super.is_staff)

    def test_superuser_no_email_or_password(self):
        cases = [
            {},
            {"email": ""},
            {"email": None},
            {"password": None},
        ]
        for i, kwargs in enumerate(cases):
            with self.subTest(**kwargs):
                superuser = User.objects.create_superuser("super{}".format(i), **kwargs)
                self.assertEqual(superuser.email, "")
                self.assertFalse(superuser.has_usable_password())

    def test_get_user_model(self):
        "The current user model can be retrieved"
        self.assertEqual(get_user_model(), User)

    @override_settings(AUTH_USER_MODEL="auth_tests.CustomUser")
    def test_swappable_user(self):
        "The current user model can be swapped out for another"
        self.assertEqual(get_user_model(), CustomUser)
        with self.assertRaises(AttributeError):
            User.objects.all()

    @override_settings(AUTH_USER_MODEL="badsetting")
    def test_swappable_user_bad_setting(self):
        "The alternate user setting must point to something in the format app.model"
        msg = "AUTH_USER_MODEL must be of the form 'app_label.model_name'"
        with self.assertRaisesMessage(ImproperlyConfigured, msg):
            get_user_model()

    @override_settings(AUTH_USER_MODEL="thismodel.doesntexist")
    def test_swappable_user_nonexistent_model(self):
        "The current user model must point to an installed model"
        msg = (
            "AUTH_USER_MODEL refers to model 'thismodel.doesntexist' "
            "that has not been installed"
        )
        with self.assertRaisesMessage(ImproperlyConfigured, msg):
            get_user_model()

    def test_user_verbose_names_translatable(self):
        "Default User model verbose names are translatable (#19945)"
        with translation.override("en"):
            self.assertEqual(User._meta.verbose_name, "user")
            self.assertEqual(User._meta.verbose_name_plural, "users")
        with translation.override("es"):
            self.assertEqual(User._meta.verbose_name, "usuario")
            self.assertEqual(User._meta.verbose_name_plural, "usuarios")


class TestGetUser(TestCase):
    def test_get_user_anonymous(self):
        request = HttpRequest()
        request.session = self.client.session
        user = get_user(request)
        self.assertIsInstance(user, AnonymousUser)

    def test_get_user(self):
        created_user = User.objects.create_user(
            "testuser", "test@example.com", "testpw"
        )
        self.client.login(username="testuser", password="testpw")
        request = HttpRequest()
        request.session = self.client.session
        user = get_user(request)
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, created_user.username)


BACKEND = "django.contrib.auth.backends.ModelBackend"


@override_settings(
    SECRET_KEY="new-secret-key",
    SECRET_KEY_FALLBACKS=["old-secret-key"],
)
class SecretKeyFallbackTests(TestCase):
    """
    Regression tests for #34611: SECRET_KEY_FALLBACKS must also be honored
    when verifying session authentication hashes, so that rotating the secret
    key doesn't log users out.
    """

    def _make_request_with_hash(self, user, session_hash, **extra_session):
        request = HttpRequest()
        request.session = self.client.session
        request.session[SESSION_KEY] = str(user.pk)
        request.session[BACKEND_SESSION_KEY] = BACKEND
        request.session[HASH_SESSION_KEY] = session_hash
        for key, value in extra_session.items():
            request.session[key] = value
        return request

    def test_get_user_with_secret_key_fallback(self):
        """
        A session hash generated with an old SECRET_KEY (now in
        SECRET_KEY_FALLBACKS) still authenticates the user, and the stored
        hash is transparently upgraded to the current SECRET_KEY.
        """
        created_user = User.objects.create_user(
            "fallback_user", "fallback@example.com", "testpw"
        )
        old_hash = created_user._get_session_auth_hash(secret="old-secret-key")
        request = self._make_request_with_hash(created_user, old_hash)

        user = get_user(request)

        self.assertIsInstance(user, User)
        self.assertEqual(user.username, created_user.username)
        # Session hash is upgraded to the current key.
        self.assertEqual(
            request.session[HASH_SESSION_KEY],
            created_user.get_session_auth_hash(),
        )

    def test_login_with_secret_key_fallback(self):
        """
        login() doesn't flush an existing session whose HASH_SESSION_KEY was
        generated with an old SECRET_KEY now in SECRET_KEY_FALLBACKS; the
        stored hash is upgraded to the current key.
        """
        created_user = User.objects.create_user(
            "login_fallback_user", "login_fallback@example.com", "testpw"
        )
        old_hash = created_user._get_session_auth_hash(secret="old-secret-key")
        request = self._make_request_with_hash(
            created_user, old_hash, custom_data="should_survive"
        )

        login(request, created_user, backend=BACKEND)

        # Session wasn't flushed — custom data survives.
        self.assertEqual(request.session.get("custom_data"), "should_survive")
        self.assertEqual(
            request.session[HASH_SESSION_KEY],
            created_user.get_session_auth_hash(),
        )

    def test_get_user_with_unknown_secret_key_is_logged_out(self):
        """
        A session hash generated with a secret not in SECRET_KEY nor
        SECRET_KEY_FALLBACKS must be rejected: get_user() returns
        AnonymousUser and flushes the session.
        """
        created_user = User.objects.create_user(
            "unknown_key_user", "unknown_key@example.com", "testpw"
        )
        # Produced with a key in neither SECRET_KEY nor SECRET_KEY_FALLBACKS.
        unknown_hash = created_user._get_session_auth_hash(
            secret="completely-unknown-secret"
        )
        request = self._make_request_with_hash(created_user, unknown_hash)

        user = get_user(request)

        self.assertIsInstance(user, AnonymousUser)
        self.assertNotIn(SESSION_KEY, request.session)

    def test_login_with_unknown_secret_key_flushes_session(self):
        """
        login() flushes a session whose HASH_SESSION_KEY was generated with a
        secret that is neither the current SECRET_KEY nor in
        SECRET_KEY_FALLBACKS.
        """
        created_user = User.objects.create_user(
            "login_unknown_key_user", "login_unknown_key@example.com", "testpw"
        )
        unknown_hash = created_user._get_session_auth_hash(
            secret="completely-unknown-secret"
        )
        request = self._make_request_with_hash(
            created_user, unknown_hash, custom_data="must_be_gone"
        )

        login(request, created_user, backend=BACKEND)

        # The flush wiped custom_data. login() unconditionally rewrites
        # HASH_SESSION_KEY, so that key is not a reliable flush indicator.
        self.assertIsNone(request.session.get("custom_data"))


class EmptySecretKeyFallbacksTests(TestCase):
    """
    With an empty SECRET_KEY_FALLBACKS, behavior must match the pre-fix
    semantics: a mismatched hash causes the session to be flushed.
    """

    @override_settings(SECRET_KEY="current-secret-key", SECRET_KEY_FALLBACKS=[])
    def test_get_user_flushes_on_mismatch_with_no_fallbacks(self):
        created_user = User.objects.create_user(
            "nofallback_user", "nofallback@example.com", "testpw"
        )
        stale_hash = created_user._get_session_auth_hash(secret="some-other-key")
        request = HttpRequest()
        request.session = self.client.session
        request.session[SESSION_KEY] = str(created_user.pk)
        request.session[BACKEND_SESSION_KEY] = BACKEND
        request.session[HASH_SESSION_KEY] = stale_hash

        user = get_user(request)

        self.assertIsInstance(user, AnonymousUser)
        self.assertNotIn(SESSION_KEY, request.session)

    @override_settings(SECRET_KEY="current-secret-key", SECRET_KEY_FALLBACKS=[])
    def test_login_flushes_on_mismatch_with_no_fallbacks(self):
        created_user = User.objects.create_user(
            "nofallback_login_user", "nofallback_login@example.com", "testpw"
        )
        stale_hash = created_user._get_session_auth_hash(secret="some-other-key")
        request = HttpRequest()
        request.session = self.client.session
        request.session[SESSION_KEY] = str(created_user.pk)
        request.session[BACKEND_SESSION_KEY] = BACKEND
        request.session[HASH_SESSION_KEY] = stale_hash
        request.session["custom_data"] = "must_be_gone"

        login(request, created_user, backend=BACKEND)

        self.assertIsNone(request.session.get("custom_data"))
