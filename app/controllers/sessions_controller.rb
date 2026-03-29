class SessionsController < ApplicationController

  def new
    # Touch the session so a session cookie is issued before authentication.
    # This ensures reset_session in log_in can rotate the session ID and
    # protect against session fixation (CWE-384).
    session[:initialized] = true
  end

  def create
    user = User.find_by(email: params[:session][:email].downcase)
    if user && user.authenticate(params[:session][:password])
      if user.activated?
        # Regenerate the session to prevent session fixation (CWE-384).
        # Preserve the forwarding URL so redirect_back_or works correctly.
        forwarding_url = session[:forwarding_url]
        reset_session
        session[:forwarding_url] = forwarding_url if forwarding_url
        log_in user
        params[:session][:remember_me] == '1' ? remember(user) : forget(user)
        redirect_back_or user
      else
        message  = "Account not activated. "
        message += "Check your email for the activation link."
        flash[:warning] = message
        redirect_to root_url
      end
    else
      flash.now[:danger] = 'Invalid email/password combination'
      render 'new'
    end
  end

  def destroy
    log_out if logged_in?
    redirect_to root_url
  end
end
