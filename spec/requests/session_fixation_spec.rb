require "rails_helper"

RSpec.describe "Session Fixation Protection", type: :request do
  before do
    @user = create(:user, email: "login_test@example.com", password: "password", password_confirmation: "password")
  end

  it "the log_in helper regenerates the session before setting user identity" do
    # Create a controller context that includes SessionsHelper
    controller = ApplicationController.new

    # Track whether reset_session is called during log_in
    session_regenerated = false
    fake_session = { canary: "attacker_data" }

    allow(controller).to receive(:session).and_return(fake_session)
    allow(controller).to receive(:reset_session) do
      session_regenerated = true
      fake_session.clear
    end

    # Call the log_in helper method
    controller.send(:log_in, @user)

    # SECURE BEHAVIOR: The session MUST be regenerated (via reset_session)
    # before setting the authenticated user's ID. Without this, an attacker
    # who fixates a known session ID before authentication can hijack the
    # victim's authenticated session after they log in.
    expect(session_regenerated).to be(true),
      "Session fixation vulnerability (CWE-384): log_in does not call reset_session. " \
      "An attacker can fixate a session ID before authentication, then hijack the " \
      "authenticated session. The log_in method must call reset_session before " \
      "setting session[:user_id]."
  end
end
