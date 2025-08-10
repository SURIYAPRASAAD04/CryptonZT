import smtplib
from email.message import EmailMessage
from datetime import datetime



SENDER_EMAIL = "cryptonzt100@gmail.com"
SENDER_PASSWORD = "zvfl npsi cyhf tpqf"

def send_attack_detect_email(email):
    
   

   
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    
    message_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Alert Notification</title>
        <style>
            /* Inline CSS for email compatibility */
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f9f9f9;
            }}
            .email-container {{
                background-color: #ffffff;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                padding: 30px;
            }}
            .header {{
                border-bottom: 1px solid #eaeaea;
                padding-bottom: 20px;
                margin-bottom: 20px;
            }}
            .logo {{
                color: #2c3e50;
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 10px;
            }}
            .alert-banner {{
                background-color: #fff8e6;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }}
            .alert-title {{
                color: #d32f2f;
                font-weight: bold;
                font-size: 18px;
                margin-bottom: 15px;
            }}
            .status-item {{
                display: flex;
                margin-bottom: 8px;
            }}
            .status-label {{
                font-weight: bold;
                min-width: 180px;
            }}
            .status-value {{
                color: #2e7d32;
            }}
            .status-value.warning {{
                color: #d32f2f;
            }}
            .footer {{
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eaeaea;
                font-size: 12px;
                color: #777777;
            }}
            .button {{
                display: inline-block;
                padding: 10px 20px;
                background-color: #4285f4;
                color: white !important;
                text-decoration: none;
                border-radius: 4px;
                font-weight: bold;
                margin: 15px 0;
            }}
            @media only screen and (max-width: 600px) {{
                body {{
                    padding: 10px;
                }}
                .email-container {{
                    padding: 20px;
                }}
                .status-label {{
                    min-width: 140px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <div class="logo">Unisys CryptonZT System</div>
                <div style="color: #777777;">Security Alert Notification</div>
            </div>
            
            <p>Dear Security Team,</p>
            
            <div class="alert-banner">
                <div class="alert-title">🚨 SECURITY ALERT: Anomaly Detected</div>
                <p>Our system has identified suspicious activity within the Quantum Escape Mechanism secure layer.</p>
            </div>
            
            <p><strong>🕒 Time of Detection:</strong> {timestamp}</p>
            
            <h3 style="margin-top: 25px; margin-bottom: 15px;">Incident Details</h3>
            <ul style="padding-left: 20px; margin-top: 0;">
                <li>An unexpected data pattern was detected by our anomaly detection model</li>
                <li>The breach attempt reached the fourth layer encapsulation</li>
                <li>Escape Protocol has been automatically triggered</li>
                <li>Data fragmentation process completed successfully</li>
            </ul>
            
            <h3 style="margin-top: 25px; margin-bottom: 15px;">System Status</h3>
            <div class="status-item">
                <div class="status-label">Backup Layer:</div>
                <div class="status-value">ACTIVATED </div>
            </div>
            <div class="status-item">
                <div class="status-label">ML Defense Response:</div>
                <div class="status-value">INITIATED </div>
            </div>
            <div class="status-item">
                <div class="status-label">Admin Notification:</div>
                <div class="status-value">DELIVERED </div>
            </div>
            <div class="status-item">
                <div class="status-label">Data Integrity:</div>
                <div class="status-value">SECURE </div>
            </div>
        
            
            <div class="footer">
                <p>This is an automated message. Please do not reply directly to this email.</p>
                <p>© {datetime.now().year} CryptonZT System. All rights reserved.</p>
            </div>
        </div>
        
        <!-- Minimal JavaScript - note most email clients will block this -->
        <script>
            // This would typically be blocked by email clients
            console.log('Security alert notification sent');
        </script>
    </body>
    </html>
    """
    
    msg = EmailMessage()
    msg.set_content(message_body)
    msg.set_content("This message contains HTML content.", subtype='plain')
    msg.add_alternative(message_body, subtype='html')
    msg['Subject'] = "⚠️ ALERT: Anomaly Detected in Key wallet"
    msg['From'] = SENDER_EMAIL
    msg['To'] = email

    try:
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)

        print(f"Message sent successfully!")

    except Exception as e:
        print(f"Failed to send email: {e}")

def send_welcome_email(recipient_email, username):
  
    login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
   
    message_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to CryptonZT</title>
        <style>
            /* Glassmorphism CSS */
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap');
            
            body {{
                font-family: 'Poppins', sans-serif;
                line-height: 1.6;
                color: white;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #E42527 0%, #f63458 50%, #ff4366 100%);
                background-attachment: fixed;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }}
            
            .email-container {{
                background: rgba(255, 255, 255, 0.15);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border-radius: 20px;
                border: 1px solid rgba(255, 255, 255, 0.18);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
                padding: 30px;
                width: 100%;
                max-width: 600px;
            }}
            
            .header {{
                text-align: center;
                padding-bottom: 20px;
                margin-bottom: 20px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.18);
            }}
            
            .logo {{
                font-size: 28px;
                font-weight: 600;
                margin-bottom: 5px;
                background: linear-gradient(to right, white, #ffe6ea);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            
            .tagline {{
                color: rgba(255, 255, 255, 0.8);
                font-weight: 300;
                font-size: 14px;
            }}
            
            .welcome-banner {{
                background: rgba(255, 255, 255, 0.2);
                border-left: 4px solid white;
                padding: 20px;
                margin: 25px 0;
                border-radius: 12px;
                backdrop-filter: blur(5px);
            }}
            
            .welcome-title {{
                font-size: 22px;
                font-weight: 500;
                margin-bottom: 10px;
                color: white;
            }}
            
            .content {{
                margin: 20px 0;
            }}
            
            .info-grid {{
                display: grid;
                grid-template-columns: 100px 1fr;
                gap: 10px;
                margin: 15px 0;
            }}
            
            .info-label {{
                font-weight: 500;
                opacity: 0.9;
            }}
            
            .info-value {{
                font-weight: 400;
            }}
            
            .button {{
                display: inline-block;
                padding: 12px 25px;
                background: rgba(255, 255, 255, 0.25);
                color: white !important;
                text-decoration: none;
                border-radius: 50px;
                font-weight: 500;
                margin: 20px 0;
                border: 1px solid rgba(255, 255, 255, 0.3);
                transition: all 0.3s ease;
                text-align: center;
            }}
            
            .button:hover {{
                background: rgba(255, 255, 255, 0.4);
            }}
            
            .steps {{
                margin: 25px 0;
                padding-left: 20px;
            }}
            
            .steps li {{
                margin-bottom: 8px;
                position: relative;
            }}
            
            .steps li:before {{
                content: "•";
                color: white;
                font-size: 20px;
                position: absolute;
                left: -15px;
                top: -3px;
            }}
            
            .footer {{
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid rgba(255, 255, 255, 0.18);
                font-size: 12px;
                color: rgba(255, 255, 255, 0.7);
                text-align: center;
            }}
            
            .footer a {{
                color: white;
                text-decoration: none;
                font-weight: 500;
            }}
            
            @media only screen and (max-width: 600px) {{
                body {{
                    padding: 15px;
                }}
                
                .email-container {{
                    padding: 20px;
                }}
                
                .info-grid {{
                    grid-template-columns: 80px 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <div class="logo">CryptonZT</div>
                <div class="tagline">Provides Quantum-Safe Security for the Blockchain Ecosystem</div>
            </div>
            
            <div class="welcome-banner">
                <div class="welcome-title">Welcome, {username}!</div>
                <p>Thank you for choosing our advanced security solution to protect your Blockchain Ecosystem assets.</p>
            </div>

            <div class="content">
                <p>We're pleased to confirm your successful login to the CryptonZT platform. Here are your details:</p>

                <div class="info-grid">
                    <div class="info-label">Username:</div>
                    <div class="info-value">{username}</div>
                    
                    <div class="info-label">Login Time:</div>
                    <div class="info-value">{login_time} (UTC)</div>
                </div>
                
                <h3 style="margin-top: 30px; margin-bottom: 15px; font-weight: 500;">Getting Started</h3>
                <p>To help you make the most of CryptonZT, we recommend:</p>
                <ul class="steps">
                    <li>Reviewing your security settings</li>
                    <li>Setting up notification preferences</li>
                    <li>Exploring the dashboard features</li>
                    <li>Configuring automated threat responses</li>
                </ul>
                
                <center>
                    <a href="https://cryptonzt.example.com/dashboard" class="button">Go to Dashboard</a>
                </center>
            </div>
            
            <div class="footer">
                <p>Need help? Contact our <a href="mailto:qdefender100@gmail.com">support team</a> or visit our <a href="https://qdefender.example.com/help">help center</a>.</p>
                <p>© {datetime.now().year} CryptonZT Security Systems. All rights reserved.</p>
                <p style="font-size: 11px; opacity: 0.6;">
                    This email was sent to {recipient_email} as part of your CryptonZT account notifications.
                    <br>If you didn't attempt to login, please secure your account immediately.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
   
    msg = EmailMessage()
    msg.set_content("This message contains HTML content.", subtype='plain')
    msg.add_alternative(message_body, subtype='html')
    msg['Subject'] = f"Welcome to CryptonZT, {username}!"
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email

    try:
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)

        print(f"Welcome email sent successfully to {recipient_email}!")

    except Exception as e:
        print(f"Failed to send email: {e}")
def send_error_report_email(user_id, error_type, error_details):
    """
    Sends an error report email to developers with standardized formatting
    
    Parameters:
        email (str): Recipient email address
        user_id (str): ID of the user who encountered the error
        error_type (str): Classification of the error (e.g., "Quantum Layer Failure")
        error_details (str): Detailed description of the error
    """
  
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
  
    system_status = "OPERATIONAL"
    alert_level = "⚠️ WARNING"
    if "critical" in error_type.lower():
        system_status = "DEGRADED"
        alert_level = "🚨 CRITICAL"
    elif "failure" in error_type.lower():
        system_status = "STABLE"
        alert_level = "⚠️ WARNING"

  
    message_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>System Error Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f9f9f9;
            }}
            .email-container {{
                background-color: #ffffff;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                padding: 30px;
            }}
            .header {{
                border-bottom: 1px solid #eaeaea;
                padding-bottom: 20px;
                margin-bottom: 20px;
                display: flex;
                align-items: center;
            }}
            .logo {{
                color: #2c3e50;
                font-size: 24px;
                font-weight: bold;
                margin-right: 15px;
            }}
            .alert-level {{
                font-size: 14px;
                padding: 4px 10px;
                border-radius: 4px;
                background-color: #fff8e6;
                color: #d32f2f;
                font-weight: bold;
            }}
            .alert-banner {{
                background-color: #f8f9fa;
                border-left: 4px solid #6c757d;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }}
            .error-title {{
                color: #d32f2f;
                font-weight: bold;
                font-size: 18px;
                margin-bottom: 15px;
            }}
            .detail-item {{
                display: flex;
                margin-bottom: 8px;
            }}
            .detail-label {{
                font-weight: bold;
                min-width: 120px;
            }}
            .detail-value {{
                color: #2c3e50;
            }}
            .system-status {{
                display: inline-block;
                padding: 4px 10px;
                border-radius: 4px;
                font-weight: bold;
                margin-top: 5px;
            }}
            .status-normal {{
                background-color: #e8f5e9;
                color: #2e7d32;
            }}
            .status-warning {{
                background-color: #fff8e1;
                color: #ff8f00;
            }}
            .status-critical {{
                background-color: #ffebee;
                color: #d32f2f;
            }}
            .footer {{
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eaeaea;
                font-size: 12px;
                color: #777777;
            }}
            @media only screen and (max-width: 600px) {{
                body {{
                    padding: 10px;
                }}
                .email-container {{
                    padding: 20px;
                }}
                .detail-label {{
                    min-width: 100px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <div class="logo">CryptonZT</div>
                <div class="alert-level">{alert_level}</div>
            </div>
            
            <p>Dear Development Team,</p>
            
            <div class="alert-banner">
                <div class="error-title">SYSTEM ERROR REPORT</div>
                <p>An error has been detected in the CryptonZT security system that requires your attention.</p>
            </div>
            
            <h3 style="margin-top: 25px; margin-bottom: 15px;">Error Details</h3>
            <div class="detail-item">
                <div class="detail-label">Timestamp:</div>
                <div class="detail-value">{timestamp}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">User ID:</div>
                <div class="detail-value">{user_id}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Error Type:</div>
                <div class="detail-value">{error_type}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">System Status:</div>
                <div class="detail-value">
                    <span class="system-status status-{system_status.lower()}">{system_status}</span>
                </div>
            </div>
            
            <h3 style="margin-top: 25px; margin-bottom: 15px;">Error Description</h3>
            <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; font-family: monospace; white-space: pre-wrap;">
                {error_details}
            </div>
            
            <h3 style="margin-top: 25px; margin-bottom: 15px;">Recommended Actions</h3>
            <ul style="padding-left: 20px; margin-top: 0;">
                <li>Review system logs for related events</li>
                <li>Check quantum encryption layer integrity</li>
                <li>Verify backup systems are operational</li>
                <li>Update incident tracking system</li>
            </ul>
            
            <div class="footer">
                <p>This is an automated error report from Q-Defender Monitoring System.</p>
                <p>© {datetime.now().year} Unisys Quantum Security. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
   
    msg = EmailMessage()
    msg.set_content(f"""
    Q-Defender Error Report
    -----------------------
    Timestamp: {timestamp}
    User ID: {user_id}
    Error Type: {error_type}
    System Status: {system_status}
    
    Error Details:
    {error_details}
    
    This is an automated error report from Q-Defender Monitoring System.
    """)
    msg.add_alternative(message_body, subtype='html')
    msg['Subject'] = f"{alert_level} {error_type} - Q-Defender Error Report"
    msg['From'] = SENDER_EMAIL
    msg['To'] = "suriyaprasaadj04@gmail.com"

    try:
     
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
        print(f"Error report sent successfully to")
    except Exception as e:
        print(f"Failed to send error report email: {e}")