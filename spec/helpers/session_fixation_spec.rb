# Standalone RSpec test for CWE-384: Session Fixation in SessionsHelper#log_in
#
# This test does NOT require the full Rails stack. It loads only the
# SessionsHelper module and uses RSpec mocks to verify that the secure
# behavior is present: reset_session MUST be called before assigning
# session[:user_id] during login to prevent session fixation attacks.
#
# RED: These tests FAIL on the current vulnerable code (no reset_session call).
# GREEN: They PASS once reset_session is added to log_in in sessions_helper.rb.

GEMS_DIR = "/github/home/.local/share/mise/installs/ruby/ruby-2.7.5/lib/ruby/gems/2.7.0/gems"

# Add available gems to the load path (no bundler, just what we need)
$LOAD_PATH.unshift("#{GEMS_DIR}/rspec-core-3.13.6/lib")
$LOAD_PATH.unshift("#{GEMS_DIR}/rspec-mocks-3.13.8/lib")
$LOAD_PATH.unshift("#{GEMS_DIR}/rspec-expectations-3.13.5/lib")
$LOAD_PATH.unshift("#{GEMS_DIR}/rspec-support-3.13.7/lib")
$LOAD_PATH.unshift("#{GEMS_DIR}/diff-lcs-1.6.2/lib")

require 'rspec'

# ---------------------------------------------------------------------------
# Load the module under test without a full Rails environment.
# The helper module has no explicit requires of its own.
# ---------------------------------------------------------------------------
require_relative '../../app/helpers/sessions_helper'

# ---------------------------------------------------------------------------
# A minimal test harness that includes SessionsHelper so we can call its
# methods directly while tracking calls to reset_session and session.
# ---------------------------------------------------------------------------
class SessionsHelperTestContext
  include SessionsHelper

  attr_reader :session_assignments, :reset_session_called

  def initialize
    @session_store         = {}
    @session_assignments   = []
    @reset_session_called  = false
    @cookies_store         = {}
  end

  # Minimal session proxy that records every assignment
  def session
    proxy = @session_store
    recorder = @session_assignments
    reset_ref = method(:was_session_reset_before_assignment)

    proxy.define_singleton_method(:[]=) do |key, value|
      recorder << { key: key, value: value, after_reset: reset_ref.call }
      super(key, value)
    end

    proxy
  end

  def cookies
    @cookies_store
  end

  # Called by the production code when session fixation is properly mitigated.
  def reset_session
    @reset_session_called = true
    @session_store = {}
  end

  private

  def was_session_reset_before_assignment
    @reset_session_called
  end
end

# ---------------------------------------------------------------------------
# Minimal user double
# ---------------------------------------------------------------------------
UserDouble = Struct.new(:id)

# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------
RSpec.describe SessionsHelper, "#log_in" do
  let(:user)    { UserDouble.new(42) }
  let(:context) { SessionsHelperTestContext.new }

  # -------------------------------------------------------------------------
  # Property-level test: the session MUST be regenerated on login.
  # The test asserts the SECURE behavior that is currently ABSENT.
  # On vulnerable code (no reset_session): fails because reset_session is
  # never called, so the pre-authentication session is reused.
  # -------------------------------------------------------------------------
  it "regenerates the session before assigning user_id (prevents CWE-384 Session Fixation)" do
    context.log_in(user)

    # SECURE requirement: reset_session must have been called during log_in
    # so the pre-authentication session token is invalidated.
    expect(context.reset_session_called).to be(true),
      "SECURITY CONTROL MISSING: log_in did not call reset_session. " \
      "Without session regeneration, an attacker who plants a session token " \
      "before the victim logs in can reuse that token to access the " \
      "authenticated session (CWE-384 Session Fixation). " \
      "Fix: call reset_session in SessionsHelper#log_in before assigning " \
      "session[:user_id]."
  end

  # -------------------------------------------------------------------------
  # Ordering guarantee: reset_session must happen BEFORE session[:user_id]
  # is set, not after (otherwise the new user_id is wiped out).
  # -------------------------------------------------------------------------
  it "resets the session BEFORE assigning session[:user_id]" do
    context.log_in(user)

    user_id_assignment = context.session_assignments.find { |a| a[:key] == :user_id }

    # If log_in does not call reset_session at all, this assertion also fails.
    expect(user_id_assignment).not_to be_nil,
      "Expected session[:user_id] to be assigned during log_in"

    expect(user_id_assignment[:after_reset]).to be(true),
      "SECURITY CONTROL MISSING: session[:user_id] was assigned BEFORE (or " \
      "without) reset_session being called. reset_session must be called first " \
      "to generate a fresh session ID, then session[:user_id] is set. " \
      "This ordering prevents session fixation (CWE-384)."
  end

  # -------------------------------------------------------------------------
  # Consequence test: a session established BEFORE log_in must NOT carry any
  # data forward into the authenticated session.
  # Without reset_session, pre-login session data persists.
  # -------------------------------------------------------------------------
  it "does not carry pre-authentication session data into the authenticated session" do
    # Simulate data that exists in the session BEFORE login
    # (e.g., data an attacker could have planted).
    context.session[:pre_auth_key] = "attacker_data"

    context.log_in(user)

    # After a proper reset_session + log_in, pre-auth data must be gone.
    expect(context.session[:pre_auth_key]).to be_nil,
      "SECURITY CONTROL MISSING: pre-authentication session data " \
      "(session[:pre_auth_key]) persisted into the authenticated session. " \
      "reset_session in log_in must clear all prior session data to prevent " \
      "an attacker-controlled session from being promoted to an " \
      "authenticated one (CWE-384 Session Fixation)."
  end
end
