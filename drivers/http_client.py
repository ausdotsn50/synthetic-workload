"""
Session-based HTTP client for Helios.
"""

import re

import requests

# The hidden input Helios's templates render. Attribute order is consistent
# across every template that emits it (see helios/templates/*.html).
_CSRF_INPUT = re.compile(
  r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']')


class HeliosSession:
  """One authenticated browser-equivalent session."""

  def __init__(self, base_url):
    self.base = base_url.rstrip('/')
    self.s = requests.Session()   # persists cookies across requests
    self._csrf = None
    # Which page to scrape the token from. Set by the login helpers, because
    # which pages are reachable depends on who is logged in.
    self._csrf_source = None

  def url(self, path):
    return f'{self.base}/{path.lstrip("/")}'

  def get(self, path, **kw):
    r = self.s.get(self.url(path), allow_redirects=True, **kw)
    r.raise_for_status()
    return r

  def learn_csrf(self, response):
    """
    Cache the token out of a response we already have.

    This is what a browser does: it receives a page, reads the hidden
    input, and submits it back. Helios's cast flow hands us the right page for
    free — POST /cast redirects to cast_confirm, and requests follows the
    redirect, so the response body is already the form we need. Scraping it here
    avoids a second GET and works for pages that only exist mid-flow.

    Returns the token, or None if this page had no form.
    """
    m = _CSRF_INPUT.search(response.text)
    if m:
      self._csrf = m.group(1)
    return self._csrf

  def csrf_token(self, source_path=None):
    """
    Helios's per-session CSRF token, scraped from a rendered form.

    Cached: the token is a session-scoped UUID that does not rotate per request,
    so one scrape serves every POST on this session.
    """
    if self._csrf:
      return self._csrf

    candidates = [p for p in (source_path, self._csrf_source,
                              '/helios/elections/new', '/') if p]
    tried = []
    for path in candidates:
      # Deliberately not self.get(): a candidate that 403s or 404s for this
      # session is expected, not an error — try the next one.
      r = self.s.get(self.url(path), allow_redirects=True)
      tried.append(f'{path} -> {r.status_code}')
      if r.status_code != 200:
        continue
      m = _CSRF_INPUT.search(r.text)
      if m:
        self._csrf = m.group(1)
        return self._csrf

    raise RuntimeError(
      'no csrf_token field found on any candidate page. Helios renders it only '
      'into templates containing a form, and only after get_user() has run. '
      'Tried: ' + '; '.join(tried))

  def post(self, path, data=None, files=None, csrf=True, expect_redirect=True,
           csrf_from=None):
    payload = dict(data or {})
    if csrf:
      payload['csrf_token'] = self.csrf_token(csrf_from)
    r = self.s.post(
      self.url(path), data=payload, files=files,
      headers={'Referer': self.url(path)},
      allow_redirects=expect_redirect)
    r.raise_for_status()
    return r

  # Auth
  def login_devlogin(self):
    """
    Log in as the fixed development user.

    devlogin (helios_auth/auth_systems/devlogin.py) authenticates as
    user@example.com unconditionally, and is refused unless DEBUG is on and the
    host is localhost/127.0.0.1. That localhost restriction is why the harness and
    the server must run on the same machine.
    """
    self.get('/auth/start/devlogin?return_url=/')
    # csrf=False: the devlogin view does not call check_csrf, and this request is
    # part of what causes get_user() to mint the session token in the first place.
    self.post('/auth/devlogin/login', data={}, csrf=False)
    r = self.get('/')
    if 'not logged in' in r.text:
      raise RuntimeError(
        'devlogin failed. Check DEBUG=1, host is localhost, and that "devlogin" is '
        'in AUTH_ENABLED_SYSTEMS.')
    # An admin can always reach the election-creation form, which carries a token.
    self._csrf_source = '/helios/elections/new'
    return self

  def login_voter(self, election_uuid, voter_id, password):
    """
    Password-auth login scoped to one election (views.password_voter_login).
    """
    self._csrf_source = f'/helios/elections/{election_uuid}/cast_confirm'
    self.post(
      f'/helios/elections/{election_uuid}/password_voter_login',
      data={'voter_id': voter_id, 'password': password, 'return_url': '/'},
      csrf=False)
    return self
