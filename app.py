from flask import Flask, render_template, request, redirect, session, flash
from model import db, User, Admin, Services, Professional, AppliedProfessional, ServiceRequest  # Import models
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize the Flask app
app = Flask(__name__)

# Set the secret key and configure the database URI
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Initialize the db with the app
db.init_app(app)
# Import models (make sure models.py has been created with the appropriate User, Admin, Services, and Professional models)

# Initialize the database
with app.app_context():
    db.create_all()  # This will create the tables if they don't exist
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])  # Hash the password
        fname = request.form['fname']
        lname = request.form.get('lname', '')  # Optional last name
        role = request.form['role']

        # Handle Service Professional Registration
        if role == 'service_professional':
            service = request.form['service']
            qualifications = request.form['qualifications']

            # Check if username already exists in AppliedProfessional or Professional
            if AppliedProfessional.query.filter_by(username=username).first():
                flash("Username already exists. Please choose a different one.", "danger")
                return redirect('/register')

            # Add to AppliedProfessional table
            new_applied_professional = AppliedProfessional(
                username=username,
                password=password,
                fname=fname,
                lname=lname,
                service=service,
                qualifications=qualifications
            )
            db.session.add(new_applied_professional)
            db.session.commit()

            flash('Application submitted! Pending admin approval.', 'success')
            return redirect('/login')

        # Handle Customer Registration
        elif role == 'customer':
            # Add to User table (no changes required here)
            new_user = User(username=username, password=password, fname=fname, lname=lname)
            db.session.add(new_user)
            db.session.commit()
            flash('Customer registered successfully!', 'success')
            return redirect('/login')

    # Fetch available services for the dropdown
    services = Services.query.all()
    return render_template('register.html', services=services)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Admin Login
        if role == 'admin':
            admin = Admin.query.filter_by(username=username).first()
            if admin and check_password_hash(admin.password, password):
                session['user_id'] = admin.aid
                session['username'] = admin.username
                session['role'] = 'admin'
                flash('Welcome, Admin!', 'success')
                return redirect('/admin/dashboard')
            else:
                flash('Invalid admin credentials.', 'danger')
                return redirect('/login')

        # Customer Login
        elif role == 'customer':
            user = User.query.filter_by(username=username).first()
            if user and not user.is_blocked:
                if check_password_hash(user.password, password):
                    session['user_id'] = user.uid
                    session['username'] = user.username
                    session['role'] = 'customer'
                    flash('Login successful!', 'success')
                    return redirect('/customer/dashboard')
                else:
                    flash('Invalid password.', 'danger')
            elif user and user.is_blocked:
                flash('Your account is blocked. Please contact the admin.', 'danger')
            else:
                flash('Invalid customer credentials.', 'danger')
                return redirect('/login')

        # Professional Login
        elif role == 'professional':
            # Check if professional exists and is blocked
            professional = Professional.query.filter_by(username=username).first()
            
            if professional and not professional.blocked:
                # Check if the password is correct
                if check_password_hash(professional.password, password):
                    session['user_id'] = professional.pid
                    session['username'] = professional.username
                    session['role'] = 'professional'
                    flash('Login successful!', 'success')
                    return redirect('/professional/dashboard')
                else:
                    flash('Invalid password.', 'danger')
            elif professional and professional.blocked:
                flash('Your account is blocked. Please contact the admin.', 'danger')
            else:
                flash('Username not found.', 'danger')

    return render_template('login.html')

@app.route('/customer/dashboard', methods=['GET', 'POST'])
def user_home():
    # Handle search functionality
    search_query = request.form.get('search', '').strip()

    if search_query:
        # Check if the search is numeric (indicating a search by service ID)
        if search_query.isdigit():
            # Search for matching service ID or service name
            services = Services.query.filter(
                (Services.sname.ilike(f"%{search_query}%")) | (Services.sid == int(search_query))
            ).all()
        else:
            # Search only by service name
            services = Services.query.filter(Services.sname.ilike(f"%{search_query}%")).all()
    else:
        # Fetch all services if no search query
        services = Services.query.all()

    # Fetch the user's previous service requests
    user_requests = ServiceRequest.query.filter_by(user_id=session['user_id']).all()

    return render_template('user_home.html', services=services, search_query=search_query, user_requests=user_requests)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect('/login')

    # Example content for admin dashboard
    return render_template('admin_home.html')


    # Query existing services and professionals
    services = Services.query.all()
    professionals = Professional.query.all()
    return render_template('admin_home.html', services=services, professionals=professionals)
@app.route('/admin/services', methods=['GET', 'POST'])
def admin_services():
    # Check if the logged-in user is an admin
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    if request.method == 'POST':
        # Get form data for adding a new service
        sid = request.form.get('sid')
        sname = request.form.get('sname')
        base_price = request.form.get('base_price')

        # Check if the service ID or name already exists
        if Services.query.filter_by(sid=sid).first():
            flash("Service ID already exists.", "danger")
        elif Services.query.filter_by(sname=sname).first():
            flash("Service Name already exists.", "danger")
        else:
            # Add the new service
            new_service = Services(sid=sid, sname=sname, base_price=base_price)
            db.session.add(new_service)
            db.session.commit()
            flash("Service added successfully!", "success")

    # Retrieve all services to display them on the page
    services = Services.query.all()
    return render_template('admin_services.html', services=services)


# Route to delete a service
@app.route('/admin/services/delete/<int:sid>', methods=['GET', 'POST'])
def delete_service(sid):
    # Fetch the service to be deleted
    service = Services.query.get(sid)

    if service:
        # Delete all associated requests
        ServiceRequest.query.filter_by(service_id=sid).delete()

        # Delete the service itself
        db.session.delete(service)
        db.session.commit()
        flash(f"Service '{service.sname}' and its associated requests were deleted successfully.", "success")
    else:
        flash("Service not found.", "danger")

    return redirect('/admin/services')


# Route to edit a service
@app.route('/admin/services/edit/<int:sid>', methods=['GET', 'POST'])
def edit_service(sid):
    service = Services.query.get(sid)
    if request.method == 'POST':
        # Get form data
        service.sname = request.form['sname']
        service.base_price = request.form['base_price']
        db.session.commit()
        flash("Service updated successfully!", "success")
        return redirect('/admin/services')

    return render_template('edit_service.html', service=service)


@app.route('/admin/professionals', methods=['GET'])
def manage_professionals():
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    # Fetch all existing professionals (approved)
    professionals = Professional.query.all()

    # Fetch all pending professional applications
    pending_professionals = AppliedProfessional.query.all()

    return render_template('admin_professional.html', professionals=professionals, pending_professionals=pending_professionals)

    # Fetch the application
    applied_professional = AppliedProfessional.query.get_or_404(id)

    # Move the approved professional to the Professional table
    new_professional = Professional(
        username=applied_professional.username,
        password=applied_professional.password,
        fname=applied_professional.fname,
        lname=applied_professional.lname,
        service=applied_professional.service,
        qualifications=applied_professional.qualifications
    )
    db.session.add(new_professional)

    # Delete the application
    db.session.delete(applied_professional)
    db.session.commit()

    flash('Professional approved and added to the system.', 'success')
    return redirect('/admin/professionals')


@app.route('/admin/professionals/edit/<int:professional_id>', methods=['POST'])
def edit_professional(professional_id):
    # Check if the logged-in user is an admin
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    # Get the professional to edit
    professional = Professional.query.get(professional_id)
    if professional:
        professional.pname = request.form['pname']
        professional.pcid = request.form['pcid']  # Updated service ID
        professional.pcount = request.form.get('pcount', professional.pcount)
        professional.pprice = request.form.get('pprice', professional.pprice)
        db.session.commit()
        flash("Professional updated successfully!", "success")
    else:
        flash("Professional not found.", "danger")

    return redirect('/admin/professionals')

@app.route('/admin/professionals/accept/<int:id>', methods=['POST'])
def accept_professional(id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    # Fetch the professional from AppliedProfessional table
    applied_professional = AppliedProfessional.query.get_or_404(id)

    # Create a new Professional entry using the data from AppliedProfessional
    new_professional = Professional(
        username=applied_professional.username,
        password=applied_professional.password,
        fname=applied_professional.fname,
        lname=applied_professional.lname,
        service=applied_professional.service,
        qualifications=applied_professional.qualifications
    )

    # Add the new professional to the Professional table
    db.session.add(new_professional)

    # Delete the professional from the AppliedProfessional table
    db.session.delete(applied_professional)
    db.session.commit()

    flash(f'{new_professional.username} has been approved and added to the system.', 'success')
    return redirect('/admin/professionals')

@app.route('/admin/professionals/reject/<int:id>', methods=['POST'])
def reject_professional(id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    # Fetch the professional application from AppliedProfessional table
    applied_professional = AppliedProfessional.query.get_or_404(id)

    # Delete the professional from the AppliedProfessional table
    db.session.delete(applied_professional)
    db.session.commit()

    flash(f'{applied_professional.username} has been rejected and removed from the system.', 'danger')
    return redirect('/admin/professionals')

@app.route('/admin/professionals/block/<int:pid>', methods=['POST'])
def block_professional(pid):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    professional = Professional.query.get_or_404(pid)
    professional.blocked = True  # Block the professional
    db.session.commit()

    flash(f'{professional.username} has been blocked.', 'warning')
    return redirect('/admin/professionals')

@app.route('/admin/professionals/unblock/<int:pid>', methods=['POST'])
def unblock_professional(pid):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    professional = Professional.query.get_or_404(pid)
    professional.blocked = False  # Unblock the professional
    db.session.commit()

    flash(f'{professional.username} has been unblocked.', 'success')
    return redirect('/admin/professionals')

@app.route('/admin/professionals/Delete/<int:pid>', methods=['POST'])
def delete_professional(pid):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    professional = Professional.query.get_or_404(pid)
    db.session.delete(professional)
    db.session.commit()

    flash(f'{professional.username} has been removed.', 'success')
    return redirect('/admin/professionals')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/user/request_service/<int:service_id>', methods=['POST'])
def request_service(service_id):
    # Fetch the service
    service = Services.query.get_or_404(service_id)

    # Create a new service request (assuming a ServiceRequest model exists)
    new_request = ServiceRequest(
        user_id=session.get('user_id'),  # Fetch the logged-in user's ID from the session
        service_id=service_id,
        status='Pending'  # Initial status for the service request
    )
    db.session.add(new_request)
    db.session.commit()

    flash(f"You have successfully requested the service: {service.sname}.", "success")
    return redirect('/customer/dashboard')

# Route to delete a service request from the pending requests
@app.route('/user/delete_request/<int:request_id>', methods=['POST'])
def delete_request(request_id):
    service_request = ServiceRequest.query.get(request_id)
    if service_request:
        db.session.delete(service_request)
        db.session.commit()
        flash('Service request deleted successfully!', 'success')
    else:
        flash('Service request not found.', 'danger')

    return redirect('/customer/dashboard')  # Redirect to the user dashboard

# Route to move a service request to the accepted_requests table
@app.route('/professional/dashboard')
def professional_dashboard():
    # Ensure the user is logged in and has the role of a professional
    if session.get('role') != 'professional':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    # Fetch the logged-in professional's record
    professional = Professional.query.filter_by(pid=session['user_id']).first()

    if not professional:
        flash("Professional record not found.", "danger")
        return redirect('/login')

    # Filter service requests for the professional's assigned service
    service_requests = ServiceRequest.query.filter_by(service_id=professional.service).all()

    # Filter requests by status
    pending_requests = [req for req in service_requests if req.status == 'Pending']
    accepted_requests = [req for req in service_requests if req.status == 'Accepted']
    completed_requests = [req for req in service_requests if req.status in ['Completed', 'Closed']]

    return render_template(
        'professional_dashboard.html',
        pending_requests=pending_requests,
        accepted_requests=accepted_requests,
        completed_requests=completed_requests,
        professional=professional
    )





@app.route('/professional/accept_request/<int:request_id>', methods=['POST'])
def accept_request(request_id):
    service_request = ServiceRequest.query.get(request_id)
    if service_request:
        # Change the status to "Accepted" in the ServiceRequest table
        service_request.status = 'Accepted'
        db.session.commit()

        flash('Service request accepted successfully!', 'success')
    else:
        flash('Service request not found.', 'danger')
    return redirect('/professional/dashboard')  # Redirect to the professional dashboard


@app.route('/professional/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    service_request = ServiceRequest.query.get(request_id)
    
    if service_request:
        # Delete the rejected request
        db.session.delete(service_request)
        db.session.commit()

        flash('Service request rejected.', 'success')
    else:
        flash('Service request not found.', 'danger')

    return redirect('/professional/dashboard')  # Redirect to the professional dashboard


@app.route('/professional/complete_request/<int:request_id>', methods=['POST'])
def complete_request(request_id):
    service_request = ServiceRequest.query.get(request_id)
    if service_request:
        # Update the status to 'Completed'
        service_request.status = 'Completed'
        service_request.closed_date = None  # Keep it open until the user closes it

        # Get the professional's review from the form
        professional_review = request.form.get('professional_review', '').strip()
        if professional_review:
            service_request.professional_review = professional_review

        db.session.commit()
        flash('Service request marked as completed and professional review submitted.', 'success')
    else:
        flash('Request not found or already completed.', 'danger')
    return redirect('/professional/dashboard')  # Redirect to the professional dashboard

@app.route('/user/close_request/<int:request_id>', methods=['POST'])
def close_request(request_id):
    service_request = ServiceRequest.query.get(request_id)

    if service_request and service_request.status == 'Completed':
        # Update the status to 'Closed'
        service_request.status = 'Closed'
        service_request.closed_date = datetime.utcnow()  # Record the closing date

        # Capture the user's review from the form
        user_review = request.form.get('review', '').strip()
        if user_review:
            service_request.user_review = user_review  # Save the review in the database
        else:
            flash('Review cannot be empty.', 'danger')
            return redirect('/customer/dashboard')

        # Commit changes to the database
        db.session.commit()
        flash('Service request closed and review submitted successfully!', 'success')
    else:
        flash('Request not found or is not ready to be closed.', 'danger')

    return redirect('/customer/dashboard')  # Redirect back to the user dashboard


@app.route('/admin/reports')
def admin_reports():
    # Ensure that the user is logged in and has the role of an admin
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    # Fetch all service requests joined with users
    all_requests = ServiceRequest.query.join(User).all()

    # Group service requests by users
    grouped_requests = {}
    for request in all_requests:
        user = request.user
        if user.username not in grouped_requests:
            grouped_requests[user.username] = []
        grouped_requests[user.username].append(request)

    return render_template('admin_reports.html', grouped_requests=grouped_requests)
@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
def block_user(user_id):
    # Ensure the user is logged in and is an admin
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    user = User.query.get(user_id)
    if user:
        # Toggle the blocked status
        user.is_blocked = not user.is_blocked
        db.session.commit()
        
        if user.is_blocked:
            flash(f"User {user.username} has been blocked.", "success")
        else:
            flash(f"User {user.username} has been unblocked.", "success")
    else:
        flash("User not found.", "danger")
    
    return redirect('/admin/reports')

@app.route('/admin/delete_request/<int:request_id>', methods=['POST'], endpoint='delete_service_request')
def delete_request(request_id):
    # Ensure the user is logged in and is an admin
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    # Get the service request from the database by ID
    service_request = ServiceRequest.query.get(request_id)

    if service_request:
        # Delete the service request
        db.session.delete(service_request)
        db.session.commit()
        flash(f"Service request {request_id} has been deleted.", "success")
    else:
        flash("Service request not found.", "danger")

    # Redirect back to the Admin Reports page
    return redirect('/admin/reports')





if __name__ == '__main__':
    app.run(debug=True)
