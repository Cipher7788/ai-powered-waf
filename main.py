if __name__ == '__main__':
    print('Running AI-Powered WAF')
    from app import app
    import os
    from dotenv import load_dotenv
    load_dotenv()
    debug = os.getenv('FLASK_DEBUG', 'False').lower() in ('1', 'true')
    port = int(os.getenv('PORT', 5000))
    app.run(debug=debug, host='0.0.0.0', port=port)
