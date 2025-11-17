from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user   # pyright: ignore[reportMissingImports]
from sqlalchemy.orm import joinedload
from flask_socketio import SocketIO, emit, join_room, leave_room

from werkzeug.security import generate_password_hash, check_password_hash  
from functools import wraps  
from werkzeug.utils import secure_filename  
import os
from PIL import Image

app = Flask(__name__)  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///onlinedelivery.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  
app.config['SECRET_KEY'] = 'hstwqkouo'  
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")


# this is for getting unique user access
login_manager=LoginManager(app)
login_manager.login_view='login'  

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Driver required decorator
def driver_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_driver:
            flash('Driver access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Models  
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    is_driver = db.Column(db.Boolean, default=False)
    vehicle_name = db.Column(db.String(100))
    license_number = db.Column(db.String(20))
    orders = db.relationship('Order', backref='user', lazy=True)

class Restaurant(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    name = db.Column(db.String(100))  
    address = db.Column(db.String(200))  
    product_picture = db.Column(db.String(1000), nullable=True)  
    orders = db.relationship('Order', back_populates='restaurant', lazy=True)  
    food_items = db.relationship('FoodItem', back_populates='restaurant', lazy=True)  

class FoodItem(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    name = db.Column(db.String(100))  
    price = db.Column(db.Float)  
    product_picture = db.Column(db.String(1000), nullable=True)  
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'))  
    restaurant = db.relationship('Restaurant', back_populates='food_items', lazy=True)        

class FoodItemOrder(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))  
    food_item_id = db.Column(db.Integer, db.ForeignKey('food_item.id'))  
    quantity = db.Column(db.Integer, default=1)  # Add quantity  
    food_item = db.relationship('FoodItem')  #add food item to be accessed  


class Order(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    total_amount = db.Column(db.Float, nullable=False)  
    status = db.Column(db.String(50))  
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  
    user_name = db.Column(db.String(100))  
    delivery_address = db.Column(db.String(255))  
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'))  # This is the foreign key  
    restaurant = db.relationship('Restaurant', back_populates='orders')  # Relationship to Restaurant  
    items = db.relationship('FoodItemOrder', backref='order', lazy=True)  # Relationship with the association table
    deliveries = db.relationship('Delivery', back_populates='order')   

class Payment(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))  
    transaction_id = db.Column(db.String(100))  
    phone_number = db.Column(db.String(20))  
    payment_method = db.Column(db.String(50))  
    user_name = db.Column(db.String(100))  # New field for user name
    order = db.relationship('Order', backref='payments', lazy=True) #Added relationship  

class Delivery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    delivery_address = db.Column(db.String(200), nullable=False)
    delivery_status = db.Column(db.String(50), default='pending')
    estimated_delivery_time = db.Column(db.String(50))
    
    # Driver information
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    driver = db.relationship('User', foreign_keys=[driver_id])
    driver_name = db.Column(db.String(100))  # NEW: Store driver name
    vehicle_name = db.Column(db.String(100))  # NEW: Store vehicle name
    license_number = db.Column(db.String(20))  # NEW: Store license plate
    
    # Location tracking
    user_latitude = db.Column(db.Float, nullable=True)
    user_longitude = db.Column(db.Float, nullable=True)
    vehicle_latitude = db.Column(db.Float, nullable=True)  # Driver's current location
    vehicle_longitude = db.Column(db.Float, nullable=True)  # Driver's current location
    
    # Delivery details
    delivery_type = db.Column(db.String(50), default='standard')
    
    # Relationships
    order = db.relationship('Order', back_populates='deliveries')


@app.route('/')
def home():
    restaurants = Restaurant.query.all()
    return render_template('index.html', restaurants=restaurants)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

# Authentication routes  
@app.route('/register', methods=['GET', 'POST'])  
def register():  
    if request.method == 'POST':  
        name = request.form['name']  
        phone = request.form['phone']  
        email = request.form['email']  
        password = request.form['password']  
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  

        first_user = User.query.first()  
        is_admin = first_user is None  # If no user exists, this one will be admin  

        # Check if the user is registering as a driver  
        is_driver = 'is_driver' in request.form  
        vehicle_name = request.form.get('vehicle_name') if is_driver else None  
        license_number = request.form.get('license_number') if is_driver else None  

        new_user = User(  
            name=name,  
            phone=phone,  
            email=email,  
            password=hashed_password,  
            is_admin=is_admin,  
            is_driver=is_driver,  
            vehicle_name=vehicle_name,  
            license_number=license_number  
        )  
        db.session.add(new_user)  
        db.session.commit()  
        flash('Registration successful! Please log in.', 'success')  
        return redirect(url_for('login'))  

    return render_template('register.html')   

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            elif current_user.is_driver:
                return redirect(url_for('driver_dashboard'))
            else:
                return redirect(url_for('list_restaurants'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    
    return render_template('login.html')

# ADMIN DASHBOARD ROUTES
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get statistics for dashboard
    total_users = User.query.count()
    total_restaurants = Restaurant.query.count()
    total_orders = Order.query.count()
    total_deliveries = Delivery.query.count()
    pending_orders = Order.query.filter_by(status='pending').count()
    
    stats = {
        'total_users': total_users,
        'total_restaurants': total_restaurants,
        'total_orders': total_orders,
        'total_deliveries': total_deliveries,
        'pending_orders': pending_orders
    }
    
    return render_template('admin/dashboard.html', stats=stats)


# Admin Manage Users
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>')
@login_required
@admin_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'phone': user.phone,
        'role': 'admin' if user.is_admin else 'driver' if user.is_driver else 'customer',
        'vehicle_name': user.vehicle_name,
        'license_number': user.license_number,
        'orders': len(user.orders)
    })

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not all([name, email, password, role]):
            flash('All fields are required!', 'error')
            return jsonify({'error': 'All fields are required'}), 400
            
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'error')
            return jsonify({'error': 'Email already exists'}), 400
            
        user = User(
            name=name,
            email=email,
            phone=phone,
            password=password,  # Note: Hash password in production
            is_admin=role == 'admin',
            is_driver=role == 'driver'
        )
        
        if role == 'driver':
            user.vehicle_name = request.form.get('vehicle_name')
            user.license_number = request.form.get('license_number')
            
        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return jsonify({'success': 'User created successfully'}), 200
        except Exception as e:
            db.session.rollback()
            flash('Error creating user!', 'error')
            return jsonify({'error': 'Error creating user'}), 500
            
    return render_template('admin/users.html')

@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.phone = request.form.get('phone')
        role = request.form.get('role')
        
        user.is_admin = role == 'admin'
        user.is_driver = role == 'driver'
        
        if role == 'driver':
            user.vehicle_name = request.form.get('vehicle_name')
            user.vehicle_license = request.form.get('license_number')
        else:
            user.vehicle_name = None
            user.vehicle_license = None
            
        if request.form.get('password'):
            user.password = request.form.get('password')  # Hash in production
            
        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return jsonify({'success': 'User updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            flash('Error updating user!', 'error')
            return jsonify({'error': 'Error updating user'}), 500

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        return jsonify({'success': 'User deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user!', 'error')
        return jsonify({'error': 'Error deleting user'}), 500
# Admin Manage Restaurants
@app.route('/admin/restaurants')
@login_required
@admin_required
def admin_restaurants():
    restaurants = Restaurant.query.all()
    return render_template('admin/restaurants.html', restaurants=restaurants)



@app.route('/admin/restaurant/create', methods=['POST'])
@login_required
@admin_required
def create_restaurant():
    name = request.form.get('name')
    address = request.form.get('address')
    
    # Handle file upload
    picture_path = None
    if 'product_picture' in request.files:
        file = request.files['product_picture']
        if file and file.filename != '':
            # Secure the filename
            filename = secure_filename(file.filename)
            
            # Create upload directory if it doesn't exist
            upload_folder = os.path.join('uploads', 'restaurants')
            os.makedirs(upload_folder, exist_ok=True)
            
            # Save the file
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            
            # Store the path for the database
            picture_path = f'restaurants/{filename}'
    
    restaurant = Restaurant(
        name=name, 
        address=address, 
        product_picture=picture_path
    )
    db.session.add(restaurant)
    db.session.commit()
    flash('Restaurant created successfully!', 'success')
    return redirect(url_for('admin_restaurants'))

@app.route('/admin/restaurant/update', methods=['POST'])
@login_required
@admin_required
def update_restaurant():
    id = request.form.get('id')
    restaurant = Restaurant.query.get_or_404(id)
    restaurant.name = request.form.get('name')
    restaurant.address = request.form.get('address')
    restaurant.product_picture = request.form.get('product_picture')
    db.session.commit()
    flash('Restaurant updated successfully!', 'success')
    return redirect(url_for('admin_restaurants'))

@app.route('/admin/restaurant/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_restaurant(id):
    restaurant = Restaurant.query.get_or_404(id)
    db.session.delete(restaurant)
    db.session.commit()
    flash('Restaurant deleted successfully!', 'success')
    return redirect(url_for('admin_restaurants'))

# Admin manage Deliveries

@app.route('/admin/deliveries')
@login_required
@admin_required
def admin_deliveries():
    deliveries = Delivery.query.options(joinedload(Delivery.order).joinedload(Order.user), joinedload(Delivery.driver)).all()
    orders = Order.query.all()
    users = User.query.all()
    drivers = User.query.filter_by(is_driver=True).all()  # Assume User model has is_driver field
    return render_template('admin/deliveries.html', deliveries=deliveries, orders=orders, users=users, drivers=drivers)

#@app.route('/admin/delivery/<int:id>')
#@login_required
#@admin_required
#def track_delivery(id):
    #delivery = Delivery.query.options(joinedload(Delivery.order).joinedload(Order.user), joinedload(Delivery.driver)).get_or_404(id)
    #return render_template('admin/track_delivery.html', delivery=delivery, current_user=current_user)

@app.route('/track_delivery/<int:id>')  # Changed from delivery_id to id
@login_required
def track_delivery(id):  # Changed parameter name to id
    """Customer tracking page"""
    delivery = Delivery.query.filter_by(id=id).first_or_404()
    
    # Verify that the customer owns this delivery
    if delivery.order.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    return render_template('track_delivery.html', delivery=delivery)

@app.route('/admin/delivery/create', methods=['POST'])
@login_required
@admin_required
def create_delivery():
    order_id = request.form.get('order_id')
    user_id = request.form.get('user_id')
    delivery_address = request.form.get('delivery_address')
    delivery_status = request.form.get('delivery_status')
    estimated_delivery_time = request.form.get('estimated_delivery_time')
    driver_id = request.form.get('driver_id')
    delivery_type = request.form.get('delivery_type')
    user_latitude = request.form.get('user_latitude')
    user_longitude = request.form.get('user_longitude')

    if not all([order_id, user_id, delivery_address, delivery_status, delivery_type]):
        flash('Order, customer, delivery address, status, and delivery type are required!', 'danger')
        return redirect(url_for('admin_deliveries'))

    try:
        order = Order.query.get_or_404(order_id)
        user = User.query.get_or_404(user_id)
        driver = User.query.get(driver_id) if driver_id else None
        user_latitude = float(user_latitude) if user_latitude else None
        user_longitude = float(user_longitude) if user_longitude else None

        delivery = Delivery(
            order_id=order_id,
            user_id=user_id,
            delivery_address=delivery_address,
            delivery_status=delivery_status,
            estimated_delivery_time=estimated_delivery_time,
            driver_id=driver_id if driver else None,
            delivery_type=delivery_type,
            user_latitude=user_latitude,
            user_longitude=user_longitude
        )
        db.session.add(delivery)
        db.session.commit()

        # Emit status update to connected clients
        socketio.emit('status_update', {
            'delivery_id': str(delivery.id),
            'status': delivery_status
        }, room=str(delivery.id))

        flash('Delivery created successfully!', 'success')
    except ValueError as e:
        flash(f'Error: Invalid latitude or longitude value.', 'danger')
    except Exception as e:
        flash(f'Error creating delivery: {str(e)}', 'danger')

    return redirect(url_for('admin_deliveries'))

@app.route('/admin/delivery/update', methods=['POST'])
@login_required
@admin_required
def update_delivery():
    id = request.form.get('id')
    order_id = request.form.get('order_id')
    user_id = request.form.get('user_id')
    delivery_address = request.form.get('delivery_address')
    delivery_status = request.form.get('delivery_status')
    estimated_delivery_time = request.form.get('estimated_delivery_time')
    driver_id = request.form.get('driver_id')
    delivery_type = request.form.get('delivery_type')
    user_latitude = request.form.get('user_latitude')
    user_longitude = request.form.get('user_longitude')

    if not all([id, order_id, user_id, delivery_address, delivery_status, delivery_type]):
        flash('All required fields must be provided!', 'danger')
        return redirect(url_for('admin_deliveries'))

    try:
        delivery = Delivery.query.get_or_404(id)
        Order.query.get_or_404(order_id)
        User.query.get_or_404(user_id)
        driver = User.query.get(driver_id) if driver_id else None
        user_latitude = float(user_latitude) if user_latitude else None
        user_longitude = float(user_longitude) if user_longitude else None

        delivery.order_id = order_id
        delivery.user_id = user_id
        delivery.delivery_address = delivery_address
        delivery.delivery_status = delivery_status
        delivery.estimated_delivery_time = estimated_delivery_time
        delivery.driver_id = driver_id if driver else None
        delivery.delivery_type = delivery_type
        delivery.user_latitude = user_latitude
        delivery.user_longitude = user_longitude

        db.session.commit()

        # Emit status update to connected clients
        socketio.emit('status_update', {
            'delivery_id': str(delivery.id),
            'status': delivery_status
        }, room=str(delivery.id))

        flash('Delivery updated successfully!', 'success')
    except ValueError as e:
        flash(f'Error: Invalid latitude or longitude value.', 'danger')
    except Exception as e:
        flash(f'Error updating delivery: {str(e)}', 'danger')

    return redirect(url_for('admin_deliveries'))

@app.route('/admin/delivery/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_delivery(id):
    try:
        delivery = Delivery.query.get_or_404(id)
        db.session.delete(delivery)
        db.session.commit()
        flash('Delivery deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting delivery: {str(e)}', 'danger')

    return redirect(url_for('admin_deliveries'))

# Socket.IO event handlers
@socketio.on('join_delivery_room')
def on_join(data):
    delivery_id = data['id']
    join_room(delivery_id)

@socketio.on('leave_delivery_room')
def on_leave(data):
    delivery_id = data['id']
    leave_room(delivery_id)

@socketio.on('update_location')
def handle_location_update(data):
    delivery_id = data['delivery_id']
    delivery = Delivery.query.get_or_404(delivery_id)
    try:
        delivery.vehicle_latitude = float(data['vehicle_latitude'])
        delivery.vehicle_longitude = float(data['vehicle_longitude'])
        db.session.commit()
        
        emit('location_update', {
            'delivery_id': str(delivery_id),
            'vehicle_latitude': delivery.vehicle_latitude,
            'vehicle_longitude': delivery.vehicle_longitude,
            'driver_name': delivery.driver.name if delivery.driver else 'Unknown'
        }, room=str(delivery_id))
    except Exception as e:
        print(f"Error updating location: {str(e)}")


# Admin manage Food Items
@app.route('/admin/food_items')
@login_required
@admin_required
def admin_food_items():
    food_items = FoodItem.query.options(joinedload(FoodItem.restaurant)).all()
    restaurants = Restaurant.query.all()
    return render_template('admin/food_items.html', food_items=food_items, restaurants=restaurants)

@app.route('/admin/food_item/create', methods=['POST'])
@login_required
@admin_required
def create_food_item():
    name = request.form.get('name')
    price = request.form.get('price')
    restaurant_id = request.form.get('restaurant_id')

    if not name or not price or not restaurant_id:
        flash('Name, price, and restaurant are required!', 'danger')
        return redirect(url_for('admin.admin_food_items'))

    try:
        price = float(price)
        if price < 0:
            raise ValueError("Price cannot be negative")
        
        restaurant = Restaurant.query.get_or_404(restaurant_id)
        
        # Handle file upload
        picture_path = None
        if 'product_picture' in request.files:
            file = request.files['product_picture']
            if file and file.filename != '':
                # Secure the filename
                filename = secure_filename(file.filename)
                
                # Create upload directory if it doesn't exist
                upload_folder = os.path.join('uploads', 'food_items')
                os.makedirs(upload_folder, exist_ok=True)
                
                # Save the file
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                
                # Store the path for the database
                picture_path = f'food_items/{filename}'
        
        food_item = FoodItem(
            name=name, 
            price=price, 
            product_picture=picture_path, 
            restaurant_id=restaurant_id
        )
        db.session.add(food_item)
        db.session.commit()
        flash('Food item created successfully!', 'success')
    except ValueError as e:
        flash(f'Error: {str(e)}', 'danger')
    except Exception:
        flash('An error occurred while creating the food item.', 'danger')

    return redirect(url_for('admin_food_items'))
@app.route('/admin/food_item/update', methods=['POST'])
@login_required
@admin_required
def update_food_item():
    id = request.form.get('id')
    name = request.form.get('name')
    price = request.form.get('price')
    product_picture = request.form.get('product_picture')
    restaurant_id = request.form.get('restaurant_id')

    if not id or not name or not price or not restaurant_id:
        flash('All fields are required!', 'danger')
        return redirect(url_for('admin_food_items'))

    try:
        price = float(price)
        if price < 0:
            raise ValueError("Price cannot be negative")
        food_item = FoodItem.query.get_or_404(id)
        Restaurant.query.get_or_404(restaurant_id)  # Validate restaurant_id
        food_item.name = name
        food_item.price = price
        food_item.product_picture = product_picture
        food_item.restaurant_id = restaurant_id
        db.session.commit()
        flash('Food item updated successfully!', 'success')
    except ValueError as e:
        flash(f'Error: {str(e)}', 'danger')
    except Exception:
        flash('An error occurred while updating the food item.', 'danger')

    return redirect(url_for('admin_food_items'))

@app.route('/admin/food_item/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_food_item(id):
    try:
        food_item = FoodItem.query.get_or_404(id)
        db.session.delete(food_item)
        db.session.commit()
        flash('Food item deleted successfully!', 'success')
    except Exception:
        flash('An error occurred while deleting the food item.', 'danger')

    return redirect(url_for('admin_food_items'))


@app.route('/admin/payments')
@login_required
@admin_required
def admin_payments():
    payments = Payment.query.options(joinedload(Payment.order)).all()
    orders = Order.query.all()
    return render_template('admin/payments.html', payments=payments, orders=orders)

@app.route('/admin/payment/create', methods=['POST'])
@login_required
@admin_required
def create_payment():
    order_id = request.form.get('order_id')
    transaction_id = request.form.get('transaction_id')
    phone_number = request.form.get('phone_number')
    payment_method = request.form.get('payment_method')
    user_name = request.form.get('user_name')

    if not all([order_id, transaction_id, phone_number, payment_method, user_name]):
        flash('All fields are required!', 'danger')
        return redirect(url_for('admin_payments'))

    try:
        order = Order.query.get_or_404(order_id)
        payment = Payment(
            order_id=order_id,
            transaction_id=transaction_id,
            phone_number=phone_number,
            payment_method=payment_method,
            user_name=user_name
        )
        db.session.add(payment)
        db.session.commit()
        flash('Payment created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating payment: {str(e)}', 'danger')

    return redirect(url_for('admin.admin_payments'))

@app.route('/admin/payment/update', methods=['POST'])
@login_required
@admin_required
def update_payment():
    id = request.form.get('id')
    order_id = request.form.get('order_id')
    transaction_id = request.form.get('transaction_id')
    phone_number = request.form.get('phone_number')
    payment_method = request.form.get('payment_method')
    user_name = request.form.get('user_name')

    if not all([id, order_id, transaction_id, phone_number, payment_method, user_name]):
        flash('All fields are required!', 'danger')
        return redirect(url_for('admin.admin_payments'))

    try:
        payment = Payment.query.get_or_404(id)
        Order.query.get_or_404(order_id)  # Validate order_id
        payment.order_id = order_id
        payment.transaction_id = transaction_id
        payment.phone_number = phone_number
        payment.payment_method = payment_method
        payment.user_name = user_name
        db.session.commit()
        flash('Payment updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating payment: {str(e)}', 'danger')

    return redirect(url_for('admin.admin_payments'))

@app.route('/admin/payment/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_payment(id):
    try:
        payment = Payment.query.get_or_404(id)
        db.session.delete(payment)
        db.session.commit()
        flash('Payment deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting payment: {str(e)}', 'danger')

    return redirect(url_for('admin_payments'))

# Admin Manage Orders
@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    orders = Order.query.order_by(Order.created_at.desc()).all()
    # Fetch all users who are drivers
    drivers = User.query.filter_by(is_driver=True).all()
    
    print(f"Found {len(drivers)} drivers")  # Debug print
    for driver in drivers:
        print(f"Driver: {driver.name}, ID: {driver.id}, Vehicle: {driver.vehicle_name}")
    
    return render_template('admin/orders.html', orders=orders, drivers=drivers)


@app.route('/admin/orders/assign-driver', methods=['POST'])
@login_required
def assign_driver():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('admin_orders'))
    
    order_id = request.form.get('order_id')
    driver_id = request.form.get('driver_id')
    estimated_time = request.form.get('estimated_delivery_time')
    delivery_type = request.form.get('delivery_type', 'standard')
    
    order = Order.query.get_or_404(order_id)
    driver = User.query.get_or_404(driver_id)
    
    # Check if driver is actually a driver
    if not driver.is_driver:
        flash('Selected user is not a driver', 'error')
        return redirect(url_for('admin_orders'))
    
    # Check if delivery already exists
    existing_delivery = Delivery.query.filter_by(order_id=order_id).first()
    
    if existing_delivery:
        # Update existing delivery
        existing_delivery.driver_id = driver_id
        existing_delivery.estimated_delivery_time = estimated_time
        existing_delivery.delivery_type = delivery_type
        existing_delivery.delivery_status = 'assigned'
    else:
        # Create new delivery
        delivery = Delivery(
            order_id=order_id,
            user_id=order.user_id,
            delivery_address=order.delivery_address,
            driver_id=driver_id,
            estimated_delivery_time=estimated_time,
            delivery_type=delivery_type,
            delivery_status='assigned'
        )
        db.session.add(delivery)
    
    # Update order status
    order.status = 'out_for_delivery'
    
    try:
        db.session.commit()
        flash(f'Driver {driver.name} assigned successfully to Order #{order_id}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error assigning driver: {str(e)}', 'error')
    
    return redirect(url_for('admin_orders'))

@app.route('/admin/orders/delete/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/orders/view/<int:order_id>')
def view_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify({
        'id': order.id,
        'user_name': order.user_name,
        'user': {'phone': order.user.phone},
        'restaurant': {'name': order.restaurant.name} if order.restaurant else None,
        'total_amount': order.total_amount,
        'status': order.status,
        'delivery_address': order.delivery_address,
        'created_at': order.created_at.isoformat(),
        'items': [{'food_item': {'name': item.food_item.name, 'price': item.food_item.price}, 'quantity': item.quantity} for item in order.items]
    })
@app.route('/admin/orders/update/<int:order_id>', methods=['POST'])
@login_required
def update_order(order_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('admin_orders'))
    
    order = Order.query.get_or_404(order_id)
    
    # Get form data
    status = request.form.get('status')
    delivery_address = request.form.get('delivery_address')
    
    # Update fields if provided
    if status:
        order.status = status
    if delivery_address:
        order.delivery_address = delivery_address
    
    try:
        db.session.commit()
        flash(f'Order #{order_id} updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating order: {str(e)}', 'error')
    
    return redirect(url_for('admin_orders'))

# WebSocket events for real-time tracking
@socketio.on('join_delivery_room')
def on_join_delivery_room(data):
    delivery_id = data['delivery_id']
    join_room(f'delivery_{delivery_id}')
    print(f'User joined delivery room: {delivery_id}')

@socketio.on('leave_delivery_room')
def on_leave_delivery_room(data):
    delivery_id = data['delivery_id']
    leave_room(f'delivery_{delivery_id}')
    print(f'User left delivery room: {delivery_id}')

def get_cart():  
    return session.get('cart', {})  

def update_cart(cart):  
    session['cart'] = cart   

# Driver routes start from here
@app.route('/driver/dashboard')
@login_required
@driver_required
def driver_dashboard():
    deliveries = (Delivery.query
                  .filter_by(driver_id=current_user.id)
                  .options(joinedload(Delivery.order).joinedload(Order.user))
                  .all())
    return render_template('driver_dashboard.html',
        deliveries=deliveries,
        user=current_user)

# ✅ 1. FIXED Start Tracking Route
@app.route('/driver/start_tracking/<int:id>', methods=['POST'])  # ✅ FIXED: <int:id>
@login_required
@driver_required
def start_tracking(id):  # ✅ Parameter matches URL
    delivery = Delivery.query.filter_by(id=id, driver_id=current_user.id).first_or_404()
    data = request.get_json()
    
    # ✅ SAVE DRIVER LOCATION TO DELIVERY TABLE
    delivery.vehicle_latitude = float(data['latitude'])
    delivery.vehicle_longitude = float(data['longitude'])
    delivery.driver_name = current_user.name
    delivery.vehicle_name = getattr(current_user, 'vehicle_name', 'Car')
    delivery.license_number = getattr(current_user, 'license_number', 'N/A')
    
    # ✅ CHANGE STATUS
    if delivery.delivery_status == 'assigned':
        delivery.delivery_status = 'in_transit'
        delivery.order.status = 'in_transit'
    
    db.session.commit()
    
    # ✅ EMIT TO ROOM
    socketio.emit('location_update', {
        'id': id,
        'vehicle_latitude': delivery.vehicle_latitude,
        'vehicle_longitude': delivery.vehicle_longitude
    }, room=f'delivery_{id}')
    
    return jsonify({
        'message': '✅ Vehicle location SAVED!', 
        'status': delivery.delivery_status,
        'vehicle_lat': delivery.vehicle_latitude,  # ✅ FOR DEBUG
        'vehicle_lng': delivery.vehicle_longitude
    })

# ✅ 2. FIXED Update Location Route
# Add this single route to your Flask app

@app.route('/driver/update_location', methods=['POST'])
@login_required
@driver_required
def update_driver_location():
    """Update driver location during delivery"""
    data = request.get_json()
    
    # Get delivery by ID or find active in-transit delivery
    delivery = None
    if 'delivery_id' in data:
        delivery = Delivery.query.filter_by(
            id=data['delivery_id'],
            driver_id=current_user.id
        ).first()
    else:
        delivery = Delivery.query.filter_by(
            driver_id=current_user.id, 
            delivery_status='in_transit'
        ).first()
    
    if not delivery:
        return jsonify({'error': 'No active delivery found'}), 404
    
    # Update vehicle location in delivery table
    delivery.vehicle_latitude = float(data['latitude'])
    delivery.vehicle_longitude = float(data['longitude'])
    
    db.session.commit()
    
    # Emit real-time update to customers via Socket.IO
    socketio.emit('location_update', {
        'id': delivery.id,
        'vehicle_latitude': delivery.vehicle_latitude,
        'vehicle_longitude': delivery.vehicle_longitude
    }, room=f'delivery_{delivery.id}')
    
    return jsonify({
        'message': 'Location updated',
        'latitude': delivery.vehicle_latitude,
        'longitude': delivery.vehicle_longitude
    })

# ✅ 3. SocketIO Events
@socketio.on('join')
def on_join(data):
    join_room(data['room'])

@socketio.on('leave')
def on_leave(data):
    leave_room(data['room'])

@app.route('/driver/update_delivery_status/<int:delivery_id>', methods=['POST'])
@login_required
@driver_required
def update_delivery_status(delivery_id):
    delivery = Delivery.query.filter_by(id=delivery_id, driver_id=current_user.id).first_or_404()
    
    new_status = request.form.get('status')
    if new_status in ['assigned', 'picked_up', 'in_transit', 'delivered', 'cancelled']:
        delivery.delivery_status = new_status
        
        # Update order status as well
        if new_status == 'delivered':
            delivery.order.status = 'completed'
        elif new_status == 'in_transit':
            delivery.order.status = 'in_transit'
            
        db.session.commit()
        
        # Emit status update to real-time tracking
        socketio.emit('status_update', {
            'delivery_id': delivery.id,
            'status': new_status
        }, room=f'delivery_{delivery.id}')
        
        flash('Delivery status updated!', 'success')
    else:
        flash('Invalid status!', 'error')
    
    return redirect(url_for('driver_dashboard'))


@app.route('/api/delivery_location/<int:delivery_id>')
@login_required
def get_delivery_location(delivery_id):
    """API endpoint to get current delivery location"""
    delivery = Delivery.query.filter_by(id=delivery_id).first_or_404()
    
    # Verify access
    if delivery.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'delivery_id': delivery.id,
        'user_latitude': delivery.user_latitude,
        'user_longitude': delivery.user_longitude,
        'vehicle_latitude': delivery.vehicle_latitude,
        'vehicle_longitude': delivery.vehicle_longitude,
        'delivery_status': delivery.delivery_status,
        'driver_name': delivery.driver.name if delivery.driver else None,
        'vehicle_name': delivery.vehicle_name,
        'license_number': delivery.license_number,
        'delivery_address': delivery.delivery_address
    })



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout SuccessFul","warning")
    return redirect(url_for('login'))

@app.route('/restaurants')  
@login_required  
def list_restaurants():  
    restaurants = Restaurant.query.all()  
    return render_template('restaurants.html', restaurants=restaurants)  

@app.route('/restaurant/<int:restaurant_id>')  
@login_required  
def restaurant_detail(restaurant_id):  
    restaurant = Restaurant.query.get_or_404(restaurant_id)  
    food_items = restaurant.food_items  
    return render_template('restaurant_detail.html', restaurant=restaurant, food_items=food_items)

@app.route('/cart')  
@login_required  
def view_cart():  
    cart = get_cart()  
    return render_template('cart.html', cart=cart)  

@app.route('/add_to_cart/<int:food_item_id>', methods=['POST'])  
@login_required  
def add_to_cart(food_item_id):  
    food_item = FoodItem.query.get_or_404(food_item_id)  
    cart = get_cart() 

    str_item_id = str(food_item_id)
    if str_item_id in cart:
        cart[str_item_id]['quantity'] += 1
    else:
        cart[str_item_id] = {'name': food_item.name, 'price': food_item.price, 'quantity': 1}
    
    update_cart(cart)  
    flash('Item added to cart!', 'success')  
    return redirect(url_for('list_restaurants'))  

@app.route('/update_cart_item/<int:food_item_id>', methods=['POST'])  
@login_required  
def update_cart_item(food_item_id):  
    cart = get_cart()  
    quantity = request.form.get('quantity', type=int)  # Get the new quantity from the form  

    # Only update if the food item is in the cart  
    if str(food_item_id) in cart:  
        if quantity is None or quantity <= 0:  
            cart.pop(str(food_item_id))  # Remove item if quantity is zero or less  
        else:  
            cart[str(food_item_id)]['quantity'] = quantity  # Update the quantity  

    # Calculate and store subtotal
    subtotal = sum(item['price'] * item['quantity'] for item in cart.values())
    session['cart_subtotal'] = subtotal
    
    update_cart(cart)
    flash('Cart updated successfully!', 'success')
    return redirect(url_for('view_cart'))  # Redirect to the cart view


@app.route('/checkout', methods=['GET', 'POST'])  
@login_required  
def checkout():  
    user = current_user  # Get the current user from Flask-Login
    if request.method == 'POST':
        transaction_id = request.form['transaction_id']
        phone_number = request.form['phone_number']
        delivery_address = request.form['delivery_address']  # Capture delivery address
        cart = get_cart()

        
        # Calculate the total amount based on updated cart quantities
        total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

        # Get restaurant ID from first cart item
        food_item_ids = list(cart.keys())
        if not food_item_ids:
            flash('Cart is empty', 'danger')
            return redirect(url_for('view_cart'))
        first_food_item = FoodItem.query.get(food_item_ids[0])
        if not first_food_item:
            flash('Invalid food item in cart', 'danger')
            return redirect(url_for('view_cart'))
        restaurant_id = first_food_item.restaurant_id

        # Create a new order with restaurant association
        new_order = Order(
            total_amount=total_amount,
            status='pending',
            user_id=current_user.id,
            user_name=user.name,
            delivery_address=delivery_address,
            restaurant_id=restaurant_id
        )
        db.session.add(new_order)
        db.session.flush()  # Get order ID without committing

        # Create food item associations
        for food_item_id, item_data in cart.items():
            food_item = FoodItem.query.get(food_item_id)
            if food_item:
                food_item_order = FoodItemOrder(
                    order_id=new_order.id,
                    food_item_id=food_item_id,
                    quantity=item_data['quantity']
                )
                db.session.add(food_item_order)

        # Create payment record
        new_payment = Payment(
            order_id=new_order.id,
            transaction_id=transaction_id,
            phone_number=phone_number,
            payment_method='MoMo',
            user_name=user.name
        )
        db.session.add(new_payment)
        db.session.commit()

        # Create delivery record
        new_delivery = Delivery(
            order_id=new_order.id,
            user_id=new_order.user_id,
            delivery_address=new_order.delivery_address,
            delivery_status='pending',
            user_latitude=request.form.get('latitude'),
            user_longitude=request.form.get('longitude')
        )
        db.session.add(new_delivery)
        db.session.commit()

        # Clear the cart
        session.pop('cart', None)
        flash('Payment processed successfully!', 'success')
        return redirect(url_for('list_restaurants'))

    return render_template('checkout.html')

@app.route('/my_orders', methods=['GET'])  
@login_required  
def my_orders():  
    if not current_user.is_authenticated:
        flash('You must be logged in to view your orders.', 'warning')
        return redirect(url_for('login'))
    
    orders = Order.query.filter_by(user_id=current_user.id).options(
        joinedload(Order.restaurant),  
        joinedload(Order.items).joinedload(FoodItemOrder.food_item)  
    ).all()  

    # Fetch payments for the retrieved orders  
    order_ids = [order.id for order in orders]  
    payments = Payment.query.filter(Payment.order_id.in_(order_ids)).all()  

    # Create a dictionary to store payments by order ID  
    payments_by_order = {payment.order_id: payment for payment in payments}  

    return render_template('my_orders.html', orders=orders, payments_by_order=payments_by_order)    

@app.route('/delivery', methods=['GET', 'POST'])
@login_required
def my_deliveries():
    deliveries = (Delivery.query
                  .filter(Delivery.user_id == current_user.id)
                  .join(Order, Delivery.order_id == Order.id)
                  .options(joinedload(Delivery.order))
                  .all())

    # Convert deliveries to dictionaries for JSON serialization
    deliveries_data = [{
        'id': d.id,
        'user_latitude': d.user_latitude,
        'user_longitude': d.user_longitude,
        'vehicle_latitude': d.vehicle_latitude,
        'vehicle_longitude': d.vehicle_longitude,
        'user_name': User.query.get(d.user_id).name if User.query.get(d.user_id) else 'N/A',
        'delivery_address': d.delivery_address,
        'delivery_status': d.delivery_status,
        'estimated_delivery_time': d.estimated_delivery_time,
        'delivery_type': d.delivery_type,
        'driver_name': d.driver.name if d.driver else 'N/A',
        'vehicle_name': d.driver.vehicle_name if d.driver else 'N/A',
        'license_number': d.driver.license_number if d.driver else 'N/A'
    } for d in deliveries]

    return render_template('delivery.html',
                         deliveries=deliveries_data,
                         mapbox_access_token='pk.eyJ1IjoiYmlzbWFyazEyMyIsImEiOiJjbTgycmdrczYwZGFtMmpyMWtnMWNwbjZiIn0.qNe9aGa_mkNcF73U_c11bA')


@app.route('/update_user_location', methods=['POST'])
@login_required
def update_user_location():
    """Endpoint for users to update their location"""
    try:
        data = request.get_json()
        latitude = float(data['latitude'])
        longitude = float(data['longitude'])
        if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            raise ValueError
            
        delivery = Delivery.query.filter_by(user_id=current_user.id).first()
        if delivery:
            delivery.user_latitude = latitude
            delivery.user_longitude = longitude
            db.session.commit()
            
        return jsonify({'message': 'Location updated'})
    except Exception as e:
        return jsonify({'message': str(e)}), 400


@app.route('/deliveries/<int:delivery_id>/start', methods=['POST'])
@login_required
def start_delivery(delivery_id):
    delivery = Delivery.query.get_or_404(delivery_id)
    if delivery.driver_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    if delivery.delivery_status != 'pending':
        return jsonify({'success': False, 'message': 'Delivery already started or completed'}), 400
    delivery.delivery_status = 'in_transit'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/deliveries/<int:delivery_id>/update-location', methods=['POST'])
@login_required
def update_location(delivery_id):
    delivery = Delivery.query.get_or_404(delivery_id)
    if delivery.driver_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    if delivery.delivery_status != 'in_transit':
        return jsonify({'success': False, 'message': 'Delivery not in transit'}), 400
    
    data = request.json
    if not data or 'latitude' not in data or 'longitude' not in data:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400
    
    delivery.vehicle_latitude = data['latitude']
    delivery.vehicle_longitude = data['longitude']
    db.session.commit()
    return jsonify({'success': True})

@app.route('/deliveries/<int:delivery_id>/complete', methods=['POST'])
@login_required
def complete_delivery(delivery_id):
    delivery = Delivery.query.get_or_404(delivery_id)
    if delivery.driver_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    if delivery.delivery_status != 'in_transit':
        return jsonify({'success': False, 'message': 'Delivery not in transit'}), 400
    delivery.delivery_status = 'delivered'
    db.session.commit()
    return jsonify({'success': True})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)