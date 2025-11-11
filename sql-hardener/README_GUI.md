# Database Security Scanner - GUI Application

A comprehensive desktop GUI application for auditing security configurations of MS SQL Server and MongoDB databases.

## Features

- **Multi-Database Support**: Scan both MS SQL Server and MongoDB instances
- **User-Friendly Interface**: Clean, intuitive desktop GUI built with Tkinter
- **Real-Time Scanning**: Live progress updates and detailed scan logs
- **AI-Powered Analysis**: Executive summaries generated using Google's Gemini AI
- **Comprehensive Reporting**: 
  - Executive summary with risk assessment
  - Detailed findings with severity levels
  - Technical report with all check results
- **Scan History**: Store and retrieve previous scan results from SQLite database
- **Export Functionality**: Export complete reports to text files

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows (tested on Windows 10/11)
- For MS SQL Server scanning: ODBC Driver 18 for SQL Server
- For MongoDB scanning: MongoDB Python driver

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configuration

1. Edit `config.ini` to set your default connection parameters
2. Add your Google Gemini API key in the `[genai]` section (optional, for AI summaries)

## Usage

### Starting the GUI Application

Run the GUI application:

```bash
python gui_app.py
```

Or on Windows, you can also run:

```bash
pythonw gui_app.py
```

### Workflow

1. **Select Database Type**
   - Choose between MS SQL Server or MongoDB
   
2. **Enter Connection Details**
   - Fill in server address, username, password
   - Optionally provide AI API key for executive summary
   
3. **Run Scan**
   - Click "Start Scan" to begin security audit
   - Monitor progress in real-time
   - View scan logs as checks are performed
   
4. **View Results**
   - Review risk assessment scores
   - Read AI-powered executive summary
   - Browse detailed findings in table view
   - Check complete technical report
   
5. **Export or Save**
   - Export reports to text files
   - Results are automatically saved to database
   
6. **View History**
   - Access previous scans from history viewer
   - Double-click any scan to view full details
   - Delete old scans if needed

## Database Storage

All scan results are automatically stored in a local SQLite database (`scan_results.db`) with the following information:

- Scan metadata (timestamp, database type, target server)
- Risk scores and finding counts
- AI-generated summaries
- Complete list of individual findings with recommendations

## Configuration File Structure

### `config.ini`

```ini
[main]
target_db = mssql  # Used by CLI mode only

[genai]
api_key = YOUR_GEMINI_API_KEY_HERE

[mssql]
module_name = checkers.check_mssql
driver = {ODBC Driver 18 for SQL Server}
server = localhost\SQLEXPRESS
database = master
username = sa

[mongodb]
module_name = checkers.check_mongodb
connection_string = mongodb://localhost:27017/
username = admin
```

## Security Checks

### MS SQL Server Checks

- xp_cmdshell status
- CLR integration
- Ad Hoc Distributed Queries
- Database Mail XPs
- Ole Automation Procedures
- SA account status and naming
- Authentication mode
- Login policies
- Linked servers
- Connection encryption
- Sysadmin role members
- TLS/SSL protocol support
- Login auditing
- SQL Server Audit configuration
- Transparent Data Encryption (TDE)
- Backup encryption
- Network exposure

### MongoDB Checks

- Authentication enabled/disabled
- Network binding configuration
- TLS/SSL mode
- Audit logging
- Authentication mechanisms (weak/deprecated)

## Risk Scoring

- **Critical findings**: 10 points each
- **Warning findings**: 3 points each

Risk Levels:
- **CRITICAL**: 50+ points
- **HIGH**: 30-49 points
- **MEDIUM**: 10-29 points
- **LOW**: 0-9 points

## Troubleshooting

### Cannot connect to MS SQL Server

- Ensure SQL Server is running
- Verify firewall settings allow connections
- Check ODBC Driver 18 is installed
- Confirm username/password are correct

### Cannot connect to MongoDB

- Verify MongoDB service is running
- Check connection string format
- Ensure authentication is properly configured

### AI Summary not generating

- Verify API key is valid
- Check internet connection
- Ensure Google Gemini API is accessible

### Database errors

- The SQLite database is created automatically
- If corrupted, delete `scan_results.db` to recreate
- Ensure write permissions in application directory

## File Structure

```
sql-hardener/
├── gui_app.py              # Main GUI application
├── scanner_controller.py   # Scanning logic controller
├── database.py             # SQLite database operations
├── main.py                 # CLI mode (original)
├── utils.py                # Utility functions
├── ai_analyzer.py          # AI summary generation
├── config.ini              # Configuration file
├── requirements.txt        # Python dependencies
├── checkers/
│   ├── check_mssql.py     # MS SQL Server checks
│   └── check_mongodb.py   # MongoDB checks
└── scan_results.db         # SQLite database (auto-created)
```

## Command-Line Mode

The original CLI mode is still available via `main.py`:

```bash
python main.py
```

CLI mode reads configuration from `config.ini` and outputs results to console.

## Contributing

When adding new database security checks:

1. Add check function to appropriate checker module
2. Follow the existing pattern with severity tags ([CRIT], [WARN], [GOOD], [INFO])
3. Include recommendations for failed checks
4. Update documentation

## License

This tool is provided as-is for database security auditing purposes.

## Support

For issues or questions, refer to the project documentation or contact the development team.

