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

class ContentSearchController < ApplicationController


  def authorize
    {
        :index => lambda{true}
    }
  end

  def index
    render :index, :locals=>{:environments=>my_environments}
  end

  def my_environments
    paths = current_organization.promotion_paths
    library = {:id=>current_organization.library.id, :name=>current_organization.library.name, :select=>true}
    paths.collect do |path|
      [library] + path.collect{|e| {:id=>e.id, :name=>e.name, :select=>true} }
    end
  end

  def errata
   render :json=>[] 
  end

  def products

    ids = params[:products][:autocomplete].collect{|p|p["id"]} if params[:products]
    if ids && !ids.empty?
      products = current_organization.products.where(:id=>ids)
    else
      products = current_organization.products
    end
    products = products.collect do |p|
       p_list = {}

       p_list['id'] = p.id
       p_list['name'] = p.name
       p_list['cols'] = p.environment_ids
       p_list
    end
    render :json=>products
  end

end