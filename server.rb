# frozen_string_literal: true

# Some of the boilerplate code is derived from GitHub's sample:
# https://developer.github.com/apps/quickstart-guides/creating-ci-tests-with-the-checks-api
#
# Modified to create a staging environment for Primer Spec Pull Requests
# by Sesh Sadasivam.

require 'fileutils'
require 'git'
require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'yaml'

set :port, 3000
set :bind, '0.0.0.0'

# The main Sinatra Application
class GHAapp < Sinatra::Application
  set :public_folder, File.dirname(__FILE__) + '/previews'

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY =
    OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # The registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # The URL at which site previews will be available
  DEPLOY_URL = ENV['DEPLOY_URL']

  # A list of whitelisted repos (Site previews will only be generated for these
  # repos.)
  # Array<Tuple<full_repo_name, site_location>>
  WHITELISTED_REPOS = JSON.parse ENV['WHITELISTED_REPOS']
  puts "Whitelisted Repos:"
  puts WHITELISTED_REPOS.inspect
  
  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature

    # This code uses the repository name in the webhook with command line
    # utilities. For security reasons, the repository name should be validated
    # to ensure that a bad actor isn't attempting to execute arbitrary
    # commands or inject false repository names. If a repository name
    # is provided in the webhook, validate that it consists only of latin
    # alphabetic characters, `-`, and `_`.
    unless @payload['repository'].nil?
      bad_name = (@payload['repository']['name'] =~ /[0-9A-Za-z\-\_]+/).nil?
      bad_full_name = (@payload['repository']['full_name'] =~ /[0-9A-Za-z\-\_]+\/[0-9A-Za-z\-\_]+/).nil?
      halt 400 if bad_name || bad_full_name

      # Only create Site Previews for whitelisted repos
      @full_repo_name, @site_location =
        WHITELISTED_REPOS.find { |full_repo_name, _|
          full_repo_name == @payload['repository']['full_name']
        }
      halt 200 unless @full_repo_name
    end

    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do
    # Get the event type from the HTTP_X_GITHUB_EVENT header
    case request.env['HTTP_X_GITHUB_EVENT']

    when 'pull_request'
      if @payload['action'] == 'opened' || @payload['action'] == 'reopened' || @payload['action'] == 'synchronize'
        init_site_preview
      elsif @payload['action'] == 'closed'
        delete_site_preview
      end
    end

    200 # success status
  end


  get '/robots.txt' do
    "User-Agent: *\nDisallow: /"
  end


  helpers do

    # Begin the Site Preview process
    def init_site_preview
      logger.debug 'Initiating site preview'

      repository       = @payload['repository']['name']
      head_sha         = @payload['pull_request']['head']['sha']
      base_sha         = @payload['pull_request']['base']['sha']
      head_repo_id     = @payload['pull_request']['head']['repo']['id']
      base_repo_id     = @payload['pull_request']['base']['repo']['id']
      pull_request_num = @payload['pull_request']['number']

      # Verify that head and base are in same repo (no forks)
      return unless head_repo_id == base_repo_id
      return unless is_number?(pull_request_num)

      clone_repository(@full_repo_name, repository, head_sha)
      chdir_to_repos

      # Prepare to generate the Site Preview

      update_gh_commit_status(head_sha, {
        state: 'pending',
        description: 'Site Preview is being prepared...',
        context: 'site-preview',
      })

      if @full_repo_name == "eecs485staff/primer-spec"
        success = build_primer_spec_pr_site(head_sha, pull_request_num)
      else
        # Check for changes that warrant a site preview
        jekyll_site_filenames = ['.html', '.htm', '.md', '.jpg', '.png']
        Dir.chdir(@full_repo_name)
        files_changed = `git diff --name-only #{head_sha} #{base_sha}`.split
        site_preview_warranted = files_changed.any? { |file|
          jekyll_site_filenames.any? { |jekyll_site_filename|
            file.include?(jekyll_site_filename)
          }
        }
        if site_preview_warranted
          chdir_to_repos
          success = build_jekyll_site(head_sha, pull_request_num)
        else
          update_gh_commit_status(head_sha, {
            state: 'success',
            description: 'No Site Preview built.',
            context: 'site-preview',
          })
          return
        end
      end

      if success
        logger.debug "Jekyll build succeeded"

        # Create the deploy directory
        chdir_to_repos
        preview_dir = "../previews/#{@full_repo_name}/#{pull_request_num}"
        FileUtils.mkdir_p(preview_dir)
        Dir.chdir preview_dir
        `rm -rf ./*`
        
        # Copy the build artifacts
        chdir_to_repos
        FileUtils.cp_r("#{@full_repo_name}/#{@site_location}/_site/.", preview_dir)
        
        # Mark the status as successful
        update_gh_commit_status(head_sha, {
          state: 'success',
          description: 'Site Preview ready!',
          context: 'site-preview',
          target_url: build_preview_url(@full_repo_name, pull_request_num),
        })
      end
    end

    def delete_site_preview
      logger.debug 'Deleting site preview'

      repository       = @payload['repository']['name']
      pull_request_num = @payload['pull_request']['number']

      return unless is_number?(pull_request_num)

      chdir_to_previews
      FileUtils.remove_dir "#{@full_repo_name}/#{pull_request_num}", :force => true
      logger.debug 'Done deleting preview'
    end

    # Clones the repository to the repos directory, updates the
    # contents using Git pull, and checks out the ref.
    #
    # full_repo_name  - The owner and repo. Ex: octocat/hello-world
    # repository      - The repository name
    # ref             - The branch, commit SHA, or tag to check out
    def clone_repository(full_repo_name, repository, ref)
      chdir_to_repos
      if not File.directory?(full_repo_name)
        # The repo hasn't been cloned before, so clone it
        owner = full_repo_name.split('/')[0]
        FileUtils.mkdir_p(owner)
        Dir.chdir(owner)
        @git = Git.clone("https://x-access-token:#{@installation_token.to_s}@github.com/#{full_repo_name}.git", repository)
        chdir_to_repos
      else
        Dir.chdir(full_repo_name)
        `git remote remove origin`
        `git remote add origin "https://x-access-token:#{@installation_token.to_s}@github.com/#{full_repo_name}.git"`
        chdir_to_repos
        @git = Git.open(full_repo_name)
      end
      # Checkout the specified commit
      Dir.chdir(full_repo_name)
      @git.reset_hard
      @git.fetch
      @git.checkout(ref)
    end

    def build_jekyll_site(head_sha, pull_request_num)
      logger.debug "Building jekyll site"

      # Copy Jekyll Gemfile to repo if not already present
      chdir_to_repos
      delete_gemfile = false
      unless File.exists?("#{@full_repo_name}/Gemfile")
        FileUtils.cp('../resources/Gemfile.jekyll', "#{@full_repo_name}/Gemfile")
        delete_gemfile = true
      end
      
      chdir_to_repos
      Dir.chdir(@full_repo_name)

      # Build the Jekyll site
      return unless install_bundle_deps(head_sha)
      logger.debug "Bundle deps installed"
      
      Dir.chdir @site_location
      delete_config_file = false
      unless File.exists?("_config.yml")
        delete_config_file = true
      end
      update_config_site_url(@full_repo_name, pull_request_num)
      logger.debug "Site URL updated in config"

      logs = `bundle exec jekyll build`
      success = $?.exitstatus == 0
      unless success
        logger.debug "Jekyll build failed. Logs:"
        logger.debug logs
        update_gh_commit_status(head_sha, {
          state: 'failure',
          description: 'Site Preview build failed',
          context: 'site-preview',
        })
      end
      chdir_to_repos
      if delete_gemfile && File.exists?("#{@full_repo_name}/Gemfile")
        FileUtils.rm("#{@full_repo_name}/Gemfile")
      end
      if delete_config_file && File.exists?("#{@site_location}/_config.yml")
        FileUtils.rm("#{@site_location}/_config.yml")
      end
      return success
    end

    def build_primer_spec_pr_site(head_sha, pull_request_num)
      logger.debug "Building Primer Spec PR"

      chdir_to_repos
      Dir.chdir(@full_repo_name)
      return unless install_bundle_deps(head_sha)
      logger.debug "Bundle deps installed"

      Dir.chdir @site_location
      update_config_site_url(@full_repo_name, pull_request_num)
      logger.debug "Site URL updated in config"

      logger.debug "Executing command: script/ci-site-preview-build \"#{build_preview_url(@full_repo_name, pull_request_num)}\""
      logs = `script/ci-site-preview-build \"#{build_preview_url(@full_repo_name, pull_request_num)}\"`
      if $?.exitstatus != 0
        logger.debug "Jekyll build failed. Logs:"
        logger.debug logs
        update_gh_commit_status(head_sha, {
          state: 'failure',
          description: 'Site Preview build failed',
          context: 'site-preview',
        })
        return false
      end
      return true
    end

    def install_bundle_deps(head_sha)
      logs = `bundle install`
      if $?.exitstatus != 0
        logger.debug "bundle install. Logs:"
        logger.debug logs
        update_gh_commit_status(head_sha, {
          state: 'failure',
          description: 'Site Preview build failed (while installing dependencies)',
          context: 'site-preview',
        })
        return false
      end
      return true
    end

    def update_config_site_url(full_repo_name, pull_request_num)
      config = {}
      if File.exists? '_config.yml'
        config = YAML.load_file('_config.yml')
      else
        config['remote_theme'] = 'pages-themes/primer'
        config['plugins'] = [
          'jekyll-remote-theme',
          'jekyll-optional-front-matter',
          'jekyll-readme-index',
          'jekyll-relative-links'
        ]
      end
      config['url'] = build_preview_url(full_repo_name, pull_request_num)
      File.open('_config.yml','w') do |h| 
        h.write config.to_yaml
     end
    end

    def chdir_to_repos
      Dir.chdir("#{__dir__}/repos")
    end

    def chdir_to_previews
      Dir.chdir("#{__dir__}/previews")
    end

    def is_number?(string)
      true if Float(string) rescue false
    end

    def build_preview_url(full_repo_name, pull_request_num)
      "#{DEPLOY_URL}/previews/#{full_repo_name}/#{pull_request_num}/"
    end

    def update_gh_commit_status(sha, payload)
      logger.debug "POST repos/#{@payload['repository']['full_name']}/statuses/#{sha}"
      logger.debug payload
      @installation_client.post(
        "repos/#{@payload['repository']['full_name']}/statuses/#{sha}",
        payload,
      )
    end

    # # # # # # # # # # # # # # # # # # #
    # BASIC GITHUB APP TEMPLATE HELPER  #
    # # # # # # # # # # # # # # # # # # #

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same (we are running this file directly), call the
  # Sinatra run method
  run! if __FILE__ == $PROGRAM_NAME
end
