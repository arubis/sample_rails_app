require "rails_helper"

RSpec.describe "Session Fixation Protection", type: :request do
  before do
    @user = create(:user, email: "login@example.com", password: "password",
                          password_confirmation: "password", activated: true)
  end

  it "regenerates the session after login to prevent session fixation" do
    # Step 1: Establish a pre-authentication session by visiting the login page
    get login_path
    expect(response).to have_http_status(:success)

    # Capture the session ID before authentication
    pre_login_session_id = session.id.to_s

    # Step 2: Log in with valid credentials
    post login_path, params: { session: { email: "login@example.com",
                                           password: "password",
                                           remember_me: "0" } }

    # Step 3: The session ID MUST change after authentication.
    # If it doesn't change, an attacker who set the session cookie before login
    # can hijack the authenticated session (CWE-384 Session Fixation).
    post_login_session_id = session.id.to_s

    expect(post_login_session_id).not_to eq(pre_login_session_id),
      "Session ID was not regenerated after login. " \
      "This allows session fixation attacks (CWE-384). " \
      "Call reset_session before setting session[:user_id]."
  end
end
