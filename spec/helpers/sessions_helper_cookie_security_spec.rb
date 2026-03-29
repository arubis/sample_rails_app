require "rails_helper"

RSpec.describe "Remember me cookie security flags", type: :request do
  before do
    @user = create(:user, email: "cookietest@example.com", password: "password",
                          password_confirmation: "password", activated: true)
  end

  it "sets remember_token cookie with httponly flag to prevent JavaScript access" do
    post login_path, params: {
      session: { email: @user.email, password: "password", remember_me: "1" }
    }

    remember_cookie = response.headers["Set-Cookie"]
      .split("\n")
      .find { |c| c.start_with?("remember_token=") }

    expect(remember_cookie).to be_present, "Expected remember_token cookie to be set"
    expect(remember_cookie.downcase).to include("httponly"),
      "remember_token cookie must have HttpOnly flag to prevent XSS-based session theft"
  end

  it "sets user_id cookie with httponly flag to prevent JavaScript access" do
    post login_path, params: {
      session: { email: @user.email, password: "password", remember_me: "1" }
    }

    user_id_cookie = response.headers["Set-Cookie"]
      .split("\n")
      .find { |c| c.start_with?("user_id=") }

    expect(user_id_cookie).to be_present, "Expected user_id cookie to be set"
    expect(user_id_cookie.downcase).to include("httponly"),
      "user_id cookie must have HttpOnly flag to prevent XSS-based session theft"
  end

  it "sets remember_token cookie with secure flag for HTTPS-only transmission" do
    post login_path, params: {
      session: { email: @user.email, password: "password", remember_me: "1" }
    }

    remember_cookie = response.headers["Set-Cookie"]
      .split("\n")
      .find { |c| c.start_with?("remember_token=") }

    expect(remember_cookie).to be_present, "Expected remember_token cookie to be set"
    expect(remember_cookie.downcase).to include("secure"),
      "remember_token cookie must have Secure flag to prevent transmission over HTTP"
  end

  it "sets user_id cookie with secure flag for HTTPS-only transmission" do
    post login_path, params: {
      session: { email: @user.email, password: "password", remember_me: "1" }
    }

    user_id_cookie = response.headers["Set-Cookie"]
      .split("\n")
      .find { |c| c.start_with?("user_id=") }

    expect(user_id_cookie).to be_present, "Expected user_id cookie to be set"
    expect(user_id_cookie.downcase).to include("secure"),
      "user_id cookie must have Secure flag to prevent transmission over HTTP"
  end
end
