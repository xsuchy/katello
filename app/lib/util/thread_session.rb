#
# Copyright 2013 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

#
# In several cases we want to break chain of responsibility in MVC a bit and provide
# a safe way to access current user (and maybe few more data items). Storing it as
# a global variable (or class member) is not thread-safe. Including ThreadSession::
# UserModel in models and ThreadSession::Controller in the application controller
# allows this without any concurrent issues.
#
# Idea taken from sentinent_user rails plugin.
#
# http://github.com/bokmann/sentient_user
# http://github.com/astrails/let_my_controller_go
# http://rails-bestpractices.com/posts/47-fetch-current-user-in-models
#


module Util
  module ThreadSession

    # include this in the User model
    module UserModel
      def self.included(base)
        base.class_eval do
          def self.current
            Thread.current[:user]
          end

          def self.current=(o)
            unless (o.nil? || o.is_a?(self) || o.class.name == 'RSpec::Mocks::Mock')
              raise(ArgumentError, "Unable to set current User, expected class '#{self}', got #{o.inspect}")
            end
            remote_id = o.is_a?(User) ? o.remote_id : 'nil'
            username = o.is_a?(User) ? o.username : 'nil'
            Rails.logger.debug "Setting current user thread-local variable to " + username
            Thread.current[:user] = o

            set_pulp_config(remote_id) if Katello.config.katello?

          end

          def self.set_pulp_config(user_id)
            if user_id
              uri = URI.parse(Katello.config.pulp.url)

              ::Runcible::Base.config = {
                :url      => "#{uri.scheme}://#{uri.host}",
                :api_path => uri.path,
                :user     => user_id,
                :oauth    => {:oauth_secret => Katello.config.pulp.oauth_secret,
                              :oauth_key    => Katello.config.pulp.oauth_key },
                :logging  => {:logger     => ::Logging.logger['pulp_rest'],
                              :exception  => true,
                              :debug      => true }
              }
            end
          end

          # Executes given block on behalf of a different user. Mostly for debuggin purposes since
          # the username is hardcoded in the codebase! Example:
          #
          # User.as :admin do
          #   ...
          # end
          #
          # Use with care!
          #
          # @param [String] username to find from the database
          # @param [block] block to execute
          def self.as(username, &do_block)
            old_user = current
            self.current = User.find_by_username(username)
            raise(ArgumentError, "Cannot find user '%s'" % username) if self.current.nil?
            do_block.call
            self.current = old_user
          end
        end
      end
    end

    # include this in the application controller
    module Controller
      def self.included(base)
        base.class_eval do
          around_filter :thread_locals
        end
      end

      def thread_locals
        # store request uuid (for Rails 3.2+ we can use Request.uuid) and process pid
        uuid = request.respond_to?(:uuid) ? request.uuid : SecureRandom.hex(16)
        ::Logging.mdc['uuid'] = Thread.current[:request_uuid] = uuid

        # store user
        u = current_user
        User.current = u

        yield

        # reset the current user (for security reasons)
        User.current = nil
      rescue => exception
        # reset the current user (for security reasons)
        User.current = nil
        raise
      end
    end
  end
end
