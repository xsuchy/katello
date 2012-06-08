/**
 Copyright 2011 Red Hat, Inc.

 This software is licensed to you under the GNU General Public
 License as published by the Free Software Foundation; either version
 2 of the License (GPLv2) or (at your option) any later version.
 There is NO WARRANTY for this software, express or implied,
 including the implied warranties of MERCHANTABILITY,
 NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
 have received a copy of GPLv2 along with this software; if not, see
 http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
*/

KT.comparison_grid = function(){
    var templates = KT.comparison_grid.templates,
        utils = KT.utils,
        columns = {},
        num_columns_shown = 0,
        num_rows = 0;

    var init = function(){
            KT.comparison_grid.events.init(this);
        },
        add_row = function(name, cell_data){
            var cells = [],
                i = 0, length = utils.size(columns);
            
            for(col in columns){
                display = utils.include(cell_data, parseInt(col)) ? true : false;
                cells.push({ 'display' : display, 'id' : col });
            }

            add_row_header(name);
            $('#grid_content').append(templates.row(utils.size(columns), cells));
            
            num_rows += 1;
        },
        add_row_header = function(name) {
            $('#grid_items').append(templates.row_header(name));
        },
        add_rows = function(data, append) {
            var i = 0, length = data.length;

            append = (append === undefined) ? true : append;

            if( !append ){
                $('#grid_content').html("");
                $('#grid_items').html("");
            }

            for(i = 0; i < length; i++){
                add_row(data[i]['name'], data[i]['cols']);
            }

            for(col in columns){
                if( columns.hasOwnProperty(col) ){
                    if( columns[col]['shown'] ){
                        $('.cell_' + col).show();
                    } else {
                        $('.cell_' + col).hide();
                    }
                }
            }
        },
        add_column = function(id, to_display, previous_column_id, data) {
            var i, column;

            add_column_header(id, to_display);
            columns[id] = { 'id' : id, 'to_display' : to_display, 'data' : data };
        },
        add_column_header = function(id, to_display) {
            $(templates.column_header(id, to_display)).insertBefore('.column_header:last');
        },
        add_columns = function(data){
            var i,
                length = data.length;

            for(i = 0; i < length; i += 1){
                add_column(data[i]['id'], data[i]['name']);
            }
        },
        show_columns = function(data){
            var i, id,
                length = data.length;

            num_columns_shown = 0;

            utils.each(columns, function(value, key){
                if( data[key] ){
                    $('#column_' + key).show();
                    columns[key]['shown'] = true;
                    num_columns_shown += 1;
                    $('.cell_' + key).show();
                } else {
                    columns[key]['shown'] = false;
                    $('#column_' + key).hide();
                    $('.cell_' + key).hide();
                }
            });
        };

    return {
        init                : init,
        add_row             : add_row,
        add_rows            : add_rows,
        add_row_header      : add_row_header,
        add_column          : add_column,
        add_columns         : add_columns,
        add_column_header   : add_column_header,
        show_columns        : show_columns
    }
};

KT.comparison_grid.events = (function() {
    var grid,

        init = function(grid_instance) {
            grid = grid_instance;

            $(document).bind('draw.comparison_grid', function(event, data){
                grid.add_rows(data, false);
            });
        };

    return {
        init : init
    };
})();

KT.comparison_grid.templates = (function() {
    var cell = function(data) {
            var display = data['display'] ? "x" : "";
            return '<span class="grid_cell cell_' + data['id'] + '">' + display + '</span>';
        },
        row = function(num_columns, cell_data) {
            var i,
                html ='<div class="grid_row">';

            for(i = 0; i < num_columns; i += 1){
                html += cell(cell_data[i]);
            }
            html += '</div>';            

            return html;
        },
        row_header = function(name) {
            var html = '<li class="row_header">';
            html += name;
            html += '</li>';
            return html;
        },
        column = function() {
        },
        column_header = function(id, to_display) {
            var html = '<li data-id="' + id  + '" id="column_' + id + '" class="column_header hidden">';
            html += to_display;
            html += '</li>';
            return html;
        };

    return {
        cell            : cell,
        row             : row,
        column_header   : column_header,
        row_header      : row_header
    }
})();