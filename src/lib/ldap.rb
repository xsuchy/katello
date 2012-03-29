#
# Copyright 2011 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

require 'net/ldap'

module Ldap
  def self.valid_ldap_authentication?(uid, password)
    ldap = LdapConnection.new
    ldap.bind? uid, password
  end

  class LdapConnection
    attr_reader :ldap, :host, :base, :group_base

    def initialize(config={})
      encryption = AppConfig.ldap.encryption
      @ldap = Net::LDAP.new(encryption.to_sym)
      @ldap.host = @host = AppConfig.ldap.host
      @base = AppConfig.ldap.base
      @group_base = AppConfig.ldap.group_base
    end

    def bind?(uid=nil, password=nil)
      @ldap.auth "uid=#{uid},#{@base}", password
      @ldap.bind
    end

    def groups_for_uid(uid)
      filter = Net::LDAP::Filter.eq("memberUid", uid)
      # group base name must be preconfigured
      treebase = group_base
      groups = []
      # groups filtering will work w/ group common names 
      ldap.search(:base => treebase, :filter => filter) do |entry|
        groups << entry[:cn]
      end
      groups
    end
  end
end
