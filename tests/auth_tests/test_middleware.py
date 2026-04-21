from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from django.test import TestCase, override_settings


class TestAuthenticationMiddleware(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            "test_user", "test@example.com", "test_password"
        )

    def setUp(self):
        self.middleware = AuthenticationMiddleware(lambda req: HttpResponse())
        self.client.force_login(self.user)
        self.request = HttpRequest()
        self.request.session = self.client.session

    def test_no_password_change_doesnt_invalidate_session(self):
        self.request.session = self.client.session
        self.middleware(self.request)
        self.assertIsNotNone(self.request.user)
        self.assertFalse(self.request.user.is_anonymous)

    def test_changed_password_invalidates_session(self):
        # After password change, user should be anonymous
        self.user.set_password("new_password")
        self.user.save()
        self.middleware(self.request)
        self.assertIsNotNone(self.request.user)
        self.assertTrue(self.request.user.is_anonymous)
        # session should be flushed
        self.assertIsNone(self.request.session.session_key)

    def test_no_session(self):
        msg = (
            "The Django authentication middleware requires session middleware "
            "to be installed. Edit your MIDDLEWARE setting to insert "
            "'django.contrib.sessions.middleware.SessionMiddleware' before "
            "'django.contrib.auth.middleware.AuthenticationMiddleware'."
        )
        with self.assertRaisesMessage(ImproperlyConfigured, msg):
            self.middleware(HttpRequest())

    async def test_auser(self):
        self.middleware(self.request)
        auser = await self.request.auser()
        self.assertEqual(auser, self.user)
        auser_second = await self.request.auser()
        self.assertIs(auser, auser_second)


class TestAuthenticationMiddlewareSecretKeyFallbacks(TestCase):
    """
    Tests that SECRET_KEY_FALLBACKS is honoured when verifying session auth
    hashes, so that users are not logged out after a SECRET_KEY rotation.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            "fallback_test_user", "fallback@example.com", "testpw"
        )

    def _build_request(self):
        request = HttpRequest()
        request.session = self.client.session
        return request

    def test_session_valid_after_key_rotation(self):
        """
        A session whose hash was produced with the old SECRET_KEY remains
        valid after rotation when the old key is listed in SECRET_KEY_FALLBACKS.
        """
        with override_settings(SECRET_KEY="oldkey"):
            self.client.force_login(self.user)
        middleware = AuthenticationMiddleware(lambda req: HttpResponse())
        with override_settings(SECRET_KEY="newkey", SECRET_KEY_FALLBACKS=["oldkey"]):
            request = self._build_request()
            middleware(request)
            # request.user is a SimpleLazyObject; force evaluation inside the
            # override_settings block so the rotated SECRET_KEY is used.
            self.assertFalse(request.user.is_anonymous)
            self.assertEqual(request.user, self.user)

    def test_session_invalid_after_fallback_removed(self):
        """
        A session whose hash was produced with an old key is invalidated once
        that key is removed from SECRET_KEY_FALLBACKS.
        """
        with override_settings(SECRET_KEY="oldkey"):
            self.client.force_login(self.user)
        middleware = AuthenticationMiddleware(lambda req: HttpResponse())
        with override_settings(SECRET_KEY="newkey", SECRET_KEY_FALLBACKS=[]):
            request = self._build_request()
            middleware(request)
            self.assertTrue(request.user.is_anonymous)

    def test_session_invalid_with_unrelated_key(self):
        """
        A session hash produced with a key that is neither SECRET_KEY nor in
        SECRET_KEY_FALLBACKS is rejected.
        """
        with override_settings(SECRET_KEY="unrelatedkey"):
            self.client.force_login(self.user)
        middleware = AuthenticationMiddleware(lambda req: HttpResponse())
        with override_settings(SECRET_KEY="newkey", SECRET_KEY_FALLBACKS=["oldkey"]):
            request = self._build_request()
            middleware(request)
            self.assertTrue(request.user.is_anonymous)
