#!/usr/bin/env python3
"""
Complete auth service with Stripe integration
Deploy this to Railway
"""

import os
import secrets
import sqlite3
import stripe
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Configuration from environment variables
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_...')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', 'whsec_...')
STRIPE_PRICE_ID = os.environ.get('STRIPE_PRICE_ID', 'price_...')
DATABASE = '/data/users.db' if os.path.exists('/data') else 'users.db'

# Initialize Stripe
stripe.api_key = STRIPE_SECRET_KEY

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            api_key TEXT UNIQUE,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            plan TEXT DEFAULT 'trial',
            expires_at INTEGER,
            max_workers INTEGER DEFAULT 1,
            created_at INTEGER DEFAULT (strftime('%s', 'now'))
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

@app.route('/auth/register', methods=['POST'])
def register():
    """Register for free trial"""
    email = request.json.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    api_key = f"mk_{secrets.token_urlsafe(32)}"
    expires = int((datetime.now() + timedelta(days=7)).timestamp())
    
    conn = sqlite3.connect(DATABASE)
    try:
        # Create Stripe customer
        customer = stripe.Customer.create(
            email=email,
            metadata={'api_key': api_key}
        )
        
        # Insert user with Stripe customer ID
        conn.execute(
            '''INSERT INTO users (email, api_key, stripe_customer_id, expires_at) 
               VALUES (?, ?, ?, ?)''',
            (email, api_key, customer.id, expires)
        )
        conn.commit()
        
        return jsonify({
            'api_key': api_key,
            'plan': 'trial',
            'trial_ends': expires
        })
        
    except sqlite3.IntegrityError:
        # User exists, return their info
        user = conn.execute(
            'SELECT api_key, plan, expires_at FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        return jsonify({
            'api_key': user[0],
            'plan': user[1],
            'existing_user': True
        })
    except stripe.error.StripeError as e:
        return jsonify({'error': 'Payment processor error ' + e}), 500
    finally:
        conn.close()

@app.route('/auth/verify', methods=['GET'])
def verify():
    """Verify API key and check subscription status"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'valid': False, 'error': 'No API key provided'}), 401
    
    conn = sqlite3.connect(DATABASE)
    user = conn.execute(
        '''SELECT email, plan, expires_at, max_workers, stripe_subscription_id 
           FROM users WHERE api_key = ?''',
        (api_key,)
    ).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'valid': False, 'error': 'Invalid API key'}), 401
    
    email, plan, expires_at, max_workers, sub_id = user
    
    # Check subscription status with Stripe if user has subscription
    if sub_id:
        try:
            subscription = stripe.Subscription.retrieve(sub_id)
            if subscription.status != 'active':
                # Downgrade to free
                conn = sqlite3.connect(DATABASE)
                conn.execute(
                    'UPDATE users SET plan = ?, max_workers = ? WHERE api_key = ?',
                    ('free', 1, api_key)
                )
                conn.commit()
                conn.close()
                return jsonify({
                    'valid': True,
                    'plan': 'free',
                    'max_workers': 1,
                    'subscription_expired': True
                })
        except stripe.error.StripeError:
            pass  # Continue with cached status
    
    # Check trial expiration
    if plan == 'trial' and expires_at < datetime.now().timestamp():
        return jsonify({
            'valid': True,
            'plan': 'trial_expired',
            'max_workers': 1,
            'trial_expired': True
        })
    
    return jsonify({
        'valid': True,
        'plan': plan,
        'max_workers': max_workers,
        'email': email
    })

@app.route('/billing/create-checkout', methods=['POST'])
def create_checkout():
    """Create Stripe checkout session for upgrade"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Get user info
    conn = sqlite3.connect(DATABASE)
    user = conn.execute(
        'SELECT email, stripe_customer_id FROM users WHERE api_key = ?',
        (api_key,)
    ).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'Invalid API key'}), 401
    
    email, customer_id = user
    
    try:
        # Create checkout session
        session = stripe.checkout.Session.create(
            customer=customer_id,
            customer_email=email if not customer_id else None,
            payment_method_types=['card'],
            line_items=[{
                'price': STRIPE_PRICE_ID,
                'quantity': 1,
            }],
            mode='subscription',
            success_url='http://localhost:3000/?upgraded=true',
            cancel_url='http://localhost:3000/',
            metadata={
                'api_key': api_key
            }
        )
        
        return jsonify({'url': session.url})
        
    except stripe.error.StripeError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/billing/cancel', methods=['POST'])
def cancel_subscription():
    """Cancel subscription"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DATABASE)
    user = conn.execute(
        'SELECT stripe_subscription_id FROM users WHERE api_key = ?',
        (api_key,)
    ).fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'No active subscription'}), 400
    
    try:
        # Cancel at period end
        stripe.Subscription.modify(
            user[0],
            cancel_at_period_end=True
        )
        
        return jsonify({'success': True, 'message': 'Subscription will cancel at period end'})
        
    except stripe.error.StripeError as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/billing/webhook', methods=['POST'])
def webhook():
    """Handle Stripe webhooks"""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify({'error': 'Invalid signature'}), 400
    
    conn = sqlite3.connect(DATABASE)
    
    # Handle checkout completed
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        api_key = session['metadata'].get('api_key')
        
        if api_key:
            # Update user to pro
            conn.execute(
                '''UPDATE users 
                   SET plan = ?, max_workers = ?, stripe_subscription_id = ?
                   WHERE api_key = ?''',
                ('pro', 8, session['subscription'], api_key)
            )
            conn.commit()
    
    # Handle subscription updated
    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        
        if subscription['status'] == 'active':
            # Reactivate
            conn.execute(
                '''UPDATE users 
                   SET plan = ?, max_workers = ?
                   WHERE stripe_subscription_id = ?''',
                ('pro', 8, subscription['id'])
            )
            conn.commit()
        elif subscription['status'] in ['canceled', 'unpaid']:
            # Downgrade
            conn.execute(
                '''UPDATE users 
                   SET plan = ?, max_workers = ?
                   WHERE stripe_subscription_id = ?''',
                ('free', 1, subscription['id'])
            )
            conn.commit()
    
    # Handle subscription deleted
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        
        # Downgrade to free
        conn.execute(
            '''UPDATE users 
               SET plan = ?, max_workers = ?, stripe_subscription_id = NULL
               WHERE stripe_subscription_id = ?''',
            ('free', 1, subscription['id'])
        )
        conn.commit()
    
    conn.close()
    return jsonify({'received': True})

@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    """Get usage statistics (protect this in production)"""
    conn = sqlite3.connect(DATABASE)
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_users,
            SUM(CASE WHEN plan = 'trial' THEN 1 ELSE 0 END) as trial_users,
            SUM(CASE WHEN plan = 'pro' THEN 1 ELSE 0 END) as pro_users,
            SUM(CASE WHEN plan = 'free' THEN 1 ELSE 0 END) as free_users
        FROM users
    ''').fetchone()
    conn.close()
    
    return jsonify({
        'total_users': stats[0],
        'trial_users': stats[1],
        'pro_users': stats[2],
        'free_users': stats[3]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)