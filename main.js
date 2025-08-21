const fs = require('fs');
const path = require('path');

// Parse CSV content into array of objects
function parseCSV(csvContent) {
    const lines = csvContent.split('\n').filter(line => line.trim());
    const headers = lines[0].split(',').map(h => h.replace(/"/g, '').trim());
    
    return lines.slice(1).map(line => {
        const values = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                values.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        values.push(current.trim());
        
        const obj = {};
        headers.forEach((header, index) => {
            obj[header] = values[index] || '';
        });
        return obj;
    });
}

// Convert system variables CSV to restricted variables
function convertSystemVariables(variables) {
    const restrictedVariables = [];
    
    variables.forEach(variable => {
        const name = variable.Name;
        const premiumAccess = variable['Access (Premium)'];
        const serverless = variable.Serverless;
        
        // Add variables that are invisible, read-only, or have specific restrictions in Premium
        if (premiumAccess === 'Invisible' || 
            premiumAccess === 'Read-only') {
            
            const restrictedVar = { name: name };
            
            // Set hidden flag based on visibility
            if (premiumAccess === 'Invisible') {
                restrictedVar.hidden = true;
            } else {
                restrictedVar.hidden = false;
            }
            
            // Add specific value overrides for certain variables
            if (name === 'hostname') {
                restrictedVar.value = 'localhost';
            }
            
            restrictedVariables.push(restrictedVar);
        }
    });
    
    return restrictedVariables;
}

// Convert privileges CSV to restricted privileges
function convertPrivileges(privileges) {
    const restrictedPrivileges = [];
    
    privileges.forEach(privilege => {
        const privilegeName = privilege.Privilege;
        const premiumAccess = privilege.Premium;
        
        // Add privileges that are not available in Premium or Serverless
        if (premiumAccess === 'NO') {
            restrictedPrivileges.push(privilegeName);
        }
    });
    
    return restrictedPrivileges;
}

// Convert system tables CSV to restricted tables
function convertSystemTables(tables) {
    const restrictedTables = [];
    
    tables.forEach(table => {
        const tableName = table['Table name'];
        const schema = table.Schema.toLowerCase();
        const premium = table.Premium;
        
        // Add tables that are not available in Premium
        if (premium === 'NO') {
            restrictedTables.push({
                "schema": schema,
                "name": tableName.toLowerCase(),
                "hidden": true
            });
        }
    });
    
    return restrictedTables;
}

// Convert SQL CSV to restricted SQL
function convertSQL(sqlData) {
    const restrictedSQL = [];
    
    sqlData.forEach(sql => {
        const sqlStatement = sql.SQL;
        const premium = sql.Premium;
        
        // Add SQL statements that are not available in Premium
        if (premium === 'NO') {
            restrictedSQL.push(sqlStatement);
        }
    });
    
    return restrictedSQL;
}

// Generate the complete SEM configuration
function generateSEMConfig(variables, privileges, tables, sqlData, options = {}) {
    const restrictedVariables = convertSystemVariables(variables);
    const restrictedPrivileges = convertPrivileges(privileges);
    const restrictedTables = convertSystemTables(tables);
    const restrictedSQL = convertSQL(sqlData);
    
    const config = {
        version: "1.0",
        tidb_version: options.tidbVersion || "v8.5.0",
        restricted_databases: options.restrictedDatabases || ["metrics_schema"],
        restricted_tables: restrictedTables,
        restricted_status_variables: options.restrictedStatusVariables || [
            "tidb_gc_leader_desc"
        ],
        restricted_variables: restrictedVariables,
        restricted_privileges: restrictedPrivileges,
        restricted_sql: {
            rule: options.restrictedRules || [
                "time_to_live",
                "alter_table_attributes", 
                "import_with_external_id"
            ],
            sql: restrictedSQL
        }
    };
    
    return config;
}

// Parse command line arguments
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {};
    
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        
        if (arg === '--tidb-version' && i + 1 < args.length) {
            options.tidbVersion = args[++i];
        } else if (arg === '--restricted-databases' && i + 1 < args.length) {
            options.restrictedDatabases = args[++i].split(',');
        } else if (arg === '--restricted-status-variables' && i + 1 < args.length) {
            options.restrictedStatusVariables = args[++i].split(',');
        } else if (arg === '--restricted-rules' && i + 1 < args.length) {
            options.restrictedRules = args[++i].split(',');
        } else if (arg === '--help' || arg === '-h') {
            console.log(`
Usage: node main.js [options]

Options:
  --tidb-version <version>              Set TiDB version (default: v8.5.0)
  --restricted-databases <db1,db2>      Set restricted databases (default: metrics_schema)
  --restricted-status-variables <vars>  Set restricted status variables (default: tidb_gc_leader_desc)
  --restricted-rules <rules>            Set restricted SQL rules (default: time_to_live,alter_table_attributes,import_with_external_id)
  --help, -h                           Show this help message
            `);
            process.exit(0);
        }
    }
    
    return options;
}

// Main execution
function main() {
    try {
        const options = parseArgs();
        
        // Read CSV files
        const variablesCSV = fs.readFileSync(
            './Security Enhancement Rules (for Cloud offering) - v8.5 - System Variables.csv', 
            'utf8'
        );
        const privilegesCSV = fs.readFileSync(
            './Security Enhancement Rules (for Cloud offering) - v8.5 - Privileges.csv', 
            'utf8'
        );
        const tablesCSV = fs.readFileSync(
            './Security Enhancement Rules (for Cloud offering) - v8.5 - System Tables.csv',
            'utf8'
        );
        const sqlCSV = fs.readFileSync(
            './Security Enhancement Rules (for Cloud offering) - v8.5 - SQL .csv',
            'utf8'
        );
        
        // Parse CSV data
        const variables = parseCSV(variablesCSV);
        const privileges = parseCSV(privilegesCSV);
        const tables = parseCSV(tablesCSV);
        const sqlData = parseCSV(sqlCSV);
        
        // Generate configuration
        const config = generateSEMConfig(variables, privileges, tables, sqlData, options);
        
        // Write output
        const outputJSON = JSON.stringify(config, null, 2);
        fs.writeFileSync('sem-config.json', outputJSON);
        
        console.log('SEM configuration generated successfully!');
        console.log(`Found ${config.restricted_variables.length} restricted variables`);
        console.log(`Found ${config.restricted_privileges.length} restricted privileges`);
        console.log(`Found ${config.restricted_tables.length} restricted tables`);
        console.log(`Found ${config.restricted_sql.sql.length} restricted SQL statements`);
        
    } catch (error) {
        console.error('Error generating SEM configuration:', error.message);
    }
}

if (require.main === module) {
    main();
}

module.exports = { parseCSV, convertSystemVariables, convertPrivileges, convertSystemTables, convertSQL, generateSEMConfig };
