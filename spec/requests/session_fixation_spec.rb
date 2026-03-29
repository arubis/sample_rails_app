require "rails_helper"

RSpec.describe "Session fixation protection", type: :request do
  before do
    @user = User.create!(
      name: "Test User",
      email: "testlogin@example.com",
      password: "password",
      password_confirmation: "password",
      activated: true,
      activated_at: Time.zone.now
    )
  end

  it "regenerates the session ID after successful authentication to prevent session fixation" do
    # Step 1: Establish a pre-authentication session by visiting a page
    get edit_user_path(@user)
    pre_login_session_id = session.id.to_s

    # Step 2: Log in with valid credentials
    post login_path, params: { session: { email: @user.email, password: "password" } }
    post_login_session_id = session.id.to_s

    # SECURE BEHAVIOR: The session ID MUST change after successful authentication.
    # If an attacker fixes the session ID before the victim logs in (session fixation),
    # regenerating the session after login invalidates the attacker's known session ID.
    # This requires calling reset_session before setting session[:user_id].
    expect(post_login_session_id).not_to eq(pre_login_session_id),
      "Session ID was not regenerated after login, allowing session fixation (CWE-384). " \
      "The log_in method must call reset_session before setting session[:user_id]."
  end
end
