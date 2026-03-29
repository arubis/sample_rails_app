require 'test_helper'

# Tests for CWE-778: Sufficient Logging of Security Events
# The UsersController#correct_user before-filter should log unauthorized
# access attempts so that incidents can be detected and investigated.
class UsersControllerSecurityLoggingTest < ActionDispatch::IntegrationTest

  def setup
    @user       = users(:michael)
    @other_user = users(:archer)
  end

  # When a logged-in user attempts to edit ANOTHER user's profile, this is
  # an unauthorized access attempt that should be recorded in the application
  # logs so that security incidents can be detected and investigated.
  test "unauthorized edit attempt by wrong user should be logged as a security event" do
    log_in_as(@other_user)

    log_output = StringIO.new
    test_logger = Logger.new(log_output)
    test_logger.formatter = proc { |severity, _datetime, _progname, msg| "#{severity}: #{msg}\n" }

    original_logger = Rails.logger
    Rails.logger = test_logger

    begin
      get edit_user_path(@user)
    ensure
      Rails.logger = original_logger
    end

    log_content = log_output.string
    assert_match(
      /unauthorized|security|wrong.?user|access.?denied|forbidden|not.?allowed|incorrect.?user/i,
      log_content,
      "Expected a security event to be logged when user '#{@other_user.email}' " \
      "attempted to edit user '#{@user.email}' — but no security-relevant log " \
      "entry was found. Unauthorized access attempts must be logged for " \
      "incident detection and investigation (CWE-778)."
    )
  end

  # When a logged-in user attempts to PATCH/update ANOTHER user's profile,
  # this unauthorized modification attempt should also be logged.
  test "unauthorized update attempt by wrong user should be logged as a security event" do
    log_in_as(@other_user)

    log_output = StringIO.new
    test_logger = Logger.new(log_output)
    test_logger.formatter = proc { |severity, _datetime, _progname, msg| "#{severity}: #{msg}\n" }

    original_logger = Rails.logger
    Rails.logger = test_logger

    begin
      patch user_path(@user), params: { user: { name: @user.name, email: @user.email } }
    ensure
      Rails.logger = original_logger
    end

    log_content = log_output.string
    assert_match(
      /unauthorized|security|wrong.?user|access.?denied|forbidden|not.?allowed|incorrect.?user/i,
      log_content,
      "Expected a security event to be logged when user '#{@other_user.email}' " \
      "attempted to update user '#{@user.email}' — but no security-relevant log " \
      "entry was found. Unauthorized modification attempts must be logged for " \
      "incident detection and investigation (CWE-778)."
    )
  end
end
