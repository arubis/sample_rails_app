require "rails_helper"

RSpec.describe "Session Fixation Protection", type: :request do
  before do
    @user = create(:user, email: "login-test@example.com", password: "password",
                          password_confirmation: "password", activated: true)
  end

  it "regenerates the session ID after successful authentication" do
    # Step 1: Establish a pre-login session by visiting the login page
    get login_path
    pre_login_session_id = request.session.id.to_s

    # Step 2: Authenticate (don't follow redirect to avoid webpacker issues)
    post login_path, params: { session: { email: @user.email,
                                          password: "password",
                                          remember_me: "0" } }

    post_login_session_id = request.session.id.to_s

    # The session ID MUST change after authentication to prevent session fixation.
    # If an attacker knows/sets the session ID before login, a new session ID
    # after login ensures the attacker's known session ID is invalidated.
    expect(post_login_session_id).not_to eq(pre_login_session_id),
      "Session ID was not regenerated after login. " \
      "This allows session fixation attacks (CWE-384). " \
      "Call reset_session before setting session[:user_id] in log_in."
  end
end
