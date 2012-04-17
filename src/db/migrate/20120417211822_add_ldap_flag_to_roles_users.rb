class AddLdapFlagToRolesUsers < ActiveRecord::Migration
  def self.up
    drop_column :roles, :ldap
    add_column :roles_users, :ldap, :boolean
  end

  def self.down
    add_column :roles, :ldap, :boolean
    drop_column :roles_users, :ldap
  end
end
