from flask import Flask, request, render_template, redirect, url_for, flash, session , jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime , timedelta
from sqlalchemy.exc import IntegrityError
import os
from sqlalchemy import func
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
db = SQLAlchemy(app)
socketio = SocketIO(app)

employee_group_association = db.Table('employee_group_association',
    db.Column('employee_id', db.Integer, db.ForeignKey('employee.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

class TaskAssignee(db.Model):
    __tablename__ = 'task_assignee'
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), primary_key=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    observer_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='new start')
    startdate = db.Column(db.Date, nullable=False)
    enddate = db.Column(db.Date, nullable=False)
    created_by = db.Column(db.String(100), nullable=False)
    summary = db.Column(db.Text)
    
    # Specify foreign_keys for relationships
    assignees = db.relationship('Employee', secondary='task_assignee', backref=db.backref('assigned_tasks', lazy='dynamic'),
                                primaryjoin="Task.id == TaskAssignee.task_id",
                                secondaryjoin="TaskAssignee.employee_id == Employee.id",
                                lazy='dynamic')
    observer = db.relationship('Employee', foreign_keys=[observer_id], lazy='select')

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    joining_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    profile_picture = db.Column(db.String(120), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    events = db.relationship('Event', backref='employee', lazy=True)
    time_entries = db.relationship('TimeEntry', backref='employee', lazy=True)
    
    # Define tasks relationship
    tasks = db.relationship('Task', backref='assigned_employee', foreign_keys=[Task.employee_id], lazy=True)

    # Define observer relationship
    observed_tasks = db.relationship('Task', backref='observer_employee', foreign_keys=[Task.observer_id], lazy=True)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    employees = db.relationship('Employee', secondary=employee_group_association, backref=db.backref('groups', lazy=True))

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    position = db.Column(db.String(150), nullable=False)
    
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)

    def __repr__(self):
        return f"<Event {self.title}>"

class TimeEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    clock_in = db.Column(db.DateTime)
    break_time = db.Column(db.DateTime)
    resume_time = db.Column(db.DateTime)
    clock_out = db.Column(db.DateTime)
    total_hours = db.Column(db.Float)

class FeedEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    admin = db.relationship('Admin', backref=db.backref('feed_entries', lazy=True))
    employee = db.relationship('Employee', backref=db.backref('feed_entries', lazy=True))


    def __repr__(self):
        return f"<FeedEntry {self.action} by {self.admin.username if self.admin else self.employee.username}>"



@app.route('/')
def startpage():
    return render_template('startpage.html')

@app.route('/attendance')
def attendance():
    if 'employee_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))
    
    employee_id = session['employee_id']
    employee = Employee.query.get(employee_id)
    
    month = request.args.get('month')
    ON_TIME_THRESHOLD = 4  # hours, adjust as needed
    LATE_THRESHOLD = 1     # hour, adjust as needed

    if month:
        month_number = datetime.strptime(month, '%B').month
        entries = TimeEntry.query.filter(
            db.extract('month', TimeEntry.date) == month_number,
            TimeEntry.employee_id == employee_id
        ).all()
        
        data = [
            {
                'date': entry.date.strftime('%a, %b %d, %Y'),
                'check_in': entry.clock_in.strftime('%I:%M %p') if entry.clock_in else 'N/A',
                'check_out': entry.clock_out.strftime('%I:%M %p') if entry.clock_out else 'N/A',
                'total_hours': entry.total_hours,
                'status': 'on-time' if entry.total_hours >= ON_TIME_THRESHOLD else 'late' if entry.total_hours < ON_TIME_THRESHOLD and entry.total_hours == LATE_THRESHOLD else 'absent'
            }
            for entry in entries
        ]
        return jsonify(data)
    
    # If no specific month is requested, calculate the attendance summary
    time_entries = TimeEntry.query.filter_by(employee_id=employee_id).all()
    total_attendance = len(time_entries)
    total_hours = sum(entry.total_hours if entry.total_hours is not None else 0 for entry in time_entries)


    # Initialize the counts
    on_time_count = sum(1 for entry in time_entries if entry.total_hours >= ON_TIME_THRESHOLD)
    late_count = sum(1 for entry in time_entries if ON_TIME_THRESHOLD > entry.total_hours >= LATE_THRESHOLD)
    absent_count = sum(1 for entry in time_entries if entry.total_hours < LATE_THRESHOLD)

    # Calculate the percentages
    on_time_percentage = (on_time_count / total_attendance) * 100 if total_attendance > 0 else 0
    late_percentage = (late_count / total_attendance) * 100 if total_attendance > 0 else 0
    absent_percentage = (absent_count / total_attendance) * 100 if total_attendance > 0 else 0

    # Calculate average check-in and check-out times
    avg_check_in = calculate_average_time([entry.clock_in for entry in time_entries if entry.clock_in])
    avg_check_out = calculate_average_time([entry.clock_out for entry in time_entries if entry.clock_out])

    return render_template(
        'attendance.html',
        employee=employee,
        time_entries=time_entries,
        total_attendance=total_attendance,
        total_hours=total_hours,
        avg_check_in=avg_check_in,
        avg_check_out=avg_check_out,
        on_time_percentage=on_time_percentage,
        late_percentage=late_percentage,
        absent_percentage=absent_percentage
    )

def calculate_average_time(times):
    """Calculate the average time from a list of time objects."""
    if not times:
        return 'N/A'
    average_time = sum(map(lambda t: t.hour * 60 + t.minute, times)) / len(times)
    average_hour, average_minute = divmod(average_time, 60)
    return datetime(1900, 1, 1, int(average_hour), int(average_minute)).strftime('%I:%M %p')



@app.route('/admin/employee/<int:id>')
def view_employee(id):
    employee = Employee.query.get_or_404(id)
    assigned_tasks = employee.assigned_tasks
    groups = employee.groups
    observed_tasks = employee.observed_tasks
    events = employee.events

    # Calculate counts for tasks, groups, and events
    task_count = len(assigned_tasks) if isinstance(assigned_tasks, list) else assigned_tasks.count()
    groups_count = len(groups) if isinstance(groups, list) else groups.count()
    observed_tasks_count = len(observed_tasks) if isinstance(observed_tasks, list) else observed_tasks.count()
    event_count = len(events) if isinstance(events, list) else events.count()

    month = request.args.get('month')
    if month:
        month_number = datetime.strptime(month, '%B').month
        time_entries = TimeEntry.query.filter(
            db.extract('month', TimeEntry.date) == month_number,
            TimeEntry.employee_id == id
        ).all()
    else:
        time_entries = employee.time_entries

    total_attendance = len(time_entries)
    total_hours = sum(entry.total_hours for entry in time_entries)

    if total_attendance > 0:
        avg_check_in_hours = sum(entry.clock_in.hour + entry.clock_in.minute / 60 for entry in time_entries if entry.clock_in) / total_attendance
        avg_check_out_hours = sum(entry.clock_out.hour + entry.clock_out.minute / 60 for entry in time_entries if entry.clock_out) / total_attendance

        avg_check_in = datetime.strptime(f"{int(avg_check_in_hours)}:{int((avg_check_in_hours % 1) * 60)}", '%H:%M').strftime('%I:%M %p')
        avg_check_out = datetime.strptime(f"{int(avg_check_out_hours)}:{int((avg_check_out_hours % 1) * 60)}", '%H:%M').strftime('%I:%M %p')
    else:
        avg_check_in = 'N/A'
        avg_check_out = 'N/A'

    on_time_count = sum(1 for entry in time_entries if entry.total_hours == 1)
    late_count = sum(1 for entry in time_entries if entry.total_hours < 1)
    absent_count = sum(1 for entry in time_entries if entry.total_hours == 0)

    if total_attendance > 0:
        on_time_percentage = (on_time_count / total_attendance) * 100
        late_percentage = (late_count / total_attendance) * 100
        absent_percentage = (absent_count / total_attendance) * 100
    else:
        on_time_percentage = 0
        late_percentage = 0
        absent_percentage = 0

    task_status_labels = list(set([task.status for task in assigned_tasks]))
    task_status_counts = [sum(1 for task in assigned_tasks if task.status == status) for status in task_status_labels]

    return render_template('view_employee.html', 
                           employee=employee, 
                           task_count=task_count, 
                           groups_count=groups_count, 
                           observed_tasks_count=observed_tasks_count,
                           event_count=event_count,
                           time_entry_dates=[entry.date.strftime('%a, %b %d, %Y') for entry in time_entries],
                           time_entry_hours=[entry.total_hours for entry in time_entries],
                           task_status_labels=task_status_labels,
                           task_status_counts=task_status_counts,
                           time_entries=time_entries,
                           total_attendance=total_attendance,
                           total_hours=total_hours,
                           avg_check_in=avg_check_in,
                           avg_check_out=avg_check_out,
                           on_time_percentage=on_time_percentage,
                           late_percentage=late_percentage,
                           absent_percentage=absent_percentage)

@app.route('/admin/list_group')
def list_group():
    groups = Group.query.all()
    return render_template('list_group.html', groups=groups)

@app.route('/employee_list', methods=['GET', 'POST'])
def employee_list():
    search_query = request.args.get('search_query')
    
    
    if search_query:
        employees = Employee.query.filter(Employee.name.ilike(f"%{search_query}%")).all()
    else:
        employees = Employee.query.all()
    employee = employees[0] if employees else None
    return render_template('employee_list.html', employees=employees, search_query=search_query, employee=employee,url_for=url_for)

@app.route('/admin/event_list', methods=['GET'])
def event_list():
    search_query = request.args.get('search_query', '')
    if search_query:
        events = Event.query.join(Employee).filter(Employee.name.contains(search_query)).all()
    else:
        events = Event.query.all()
    return render_template('event_list.html', events=events, search_query=search_query)


@app.route('/attendance_list', methods=['GET'])
def attendance_list():
    search_query = request.args.get('search_query')
    
    if search_query:
        time_entries = db.session.query(TimeEntry).join(Employee).filter(Employee.username.ilike(f"%{search_query}%")).all()
    else:
        time_entries = TimeEntry.query.all()
    employees = Employee.query.all()
    return render_template('attendance_list.html', time_entries=time_entries, search_query=search_query , employees=employees)

@app.route('/admincalender')
def admincalender():
    events = Event.query.all()
    return render_template('admincalender.html',events=events)


@app.route('/admin/admintasklist', methods=['GET'])
def admintasklist():
    search_query = request.args.get('search_query', '')

    if search_query:
        # Assuming Task model has a 'title' attribute
        tasks = db.session.query(Task).filter(Task.title.ilike(f'%{search_query}%')).all()
    else:
        tasks = db.session.query(Task).all()

    # Prepare task data including assignees and observers
    tasks_data = []
    for task in tasks:
        assignees = task.assignees.all()
        observer = task.observer_employee
        assigned_employee = task.assigned_employee
        tasks_data.append({
            'task': task,
            'employee': assigned_employee,
            'assignees': assignees,
            'observer': observer
        })

    return render_template('admintasklist.html', tasks=tasks_data, search_query=search_query)


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        position = request.form['position']
        hashed_password = generate_password_hash(password)
        
        new_admin = Admin(username=username, password=hashed_password, email=email, position=position)
        
        try:
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin registration successful! Please log in.', 'success')
            return redirect(url_for('admin_login'))
        except IntegrityError:
            db.session.rollback()
            flash('Admin username already exists. Please choose a different one.', 'danger')
    
    return render_template('admin_register.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['is_admin'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin credentials', 'danger')
    
    return render_template('admin_login.html')

@app.route('/admin')
def admin():
    today = datetime.today().date()
    
    # Query tasks, events, and time entries for today
    tasks_today = Task.query.filter(func.date(Task.startdate) == today).all()
    events_today = Event.query.filter(func.date(Event.date) == today).all()
    time_entries_today = TimeEntry.query.filter(func.date(TimeEntry.date) == today).all()

    # Counts for today's entries
    task_count_today = len(tasks_today)
    event_count_today = len(events_today)
    time_entry_count_today = len(time_entries_today)

    # Total counts for various models
    task_count_total = Task.query.count()
    groups_count = Group.query.count()
    employee_count = Employee.query.count()
    event_count_total = Event.query.count()
    time_entry_count_total = TimeEntry.query.count()

    # Time entry data
    time_entries = TimeEntry.query.all()
    time_entry_dates = [entry.date.strftime('%Y-%m-%d') for entry in time_entries]
    time_entry_hours = [entry.total_hours for entry in time_entries]

    # Task status data
    task_statuses = db.session.query(Task.status, db.func.count(Task.status)).group_by(Task.status).all()
    task_status_labels = [status for status, count in task_statuses]
    task_status_counts = [count for status, count in task_statuses]

    tasks = Task.query.all()

    # Logic to get today's employees data
    employees_data = []
    for entry in time_entries_today:
        total_hours = 0
        if entry.clock_in and entry.clock_out:
            total_hours = (entry.clock_out - entry.clock_in).total_seconds() / 3600  # convert seconds to hours
        employee = Employee.query.get(entry.employee_id)
        if employee:
            employees_data.append({
                'profile_picture': employee.profile_picture,
                'name': employee.name,
                'clock_in': entry.clock_in,
                'clock_out': entry.clock_out,
                'total_hours': total_hours
            })

    return render_template('admin.html',
                           task_count_total=task_count_total,
                           time_entry_count_total=time_entry_count_total,
                           event_count_total=event_count_total,
                           task_count=task_count_today,
                           groups_count=groups_count,
                           employee_count=employee_count,
                           event_count=event_count_today,
                           time_entry_count=time_entry_count_today,
                           time_entry_dates=time_entry_dates,
                           time_entry_hours=time_entry_hours,
                           task_status_labels=task_status_labels,
                           task_status_counts=task_status_counts,
                           tasks=tasks,
                           events=events_today,
                           time_entries=time_entries_today,
                           username="Admin",
                           employees=employees_data)

"""@app.route('/admin/add_employee', methods=['GET', 'POST'])
def add_employee():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        position = request.form['position']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        joining_date = datetime.strptime(request.form['joining_date'], '%Y-%m-%d')
        

        new_employee = Employee(name=name, email=email, position=position, joining_date=joining_date, username=username, password=hashed_password)
        
        db.session.add(new_employee)
        db.session.commit()
        flash('Employee added successfully!', 'success')
        return redirect(url_for('employee_list'))
    
    employees = Employee.query.all()
    groups = Group.query.all()
    return render_template('add_employee.html', groups=groups, employees=employees)

@app.route('/admin/update_employee/<int:id>', methods=['GET', 'POST'])
def update_employee(id):
    employee = Employee.query.get_or_404(id)
    if request.method == 'POST':
        employee.name = request.form['name']
        employee.email = request.form['email']
        employee.position = request.form['position']
        employee.joining_date = datetime.strptime(request.form['joining_date'], '%Y-%m-%d')
        group_ids = request.form.getlist('group_ids')

        # Clear existing groups
        employee.groups = []

        for group_id in group_ids:
            group = Group.query.get(group_id)
            employee.groups.append(group)

        db.session.commit()
       
        flash('Employee updated successfully!', 'success')
        return redirect(url_for('employee_list', id=employee.id))
    
    groups = Group.query.all()
    return render_template('update_employee.html', employee=employee, groups=groups)"""

@app.route('/admin/add_employee_group/<int:id>', methods=['GET', 'POST'])
def add_employee_group(id):
    employee = Employee.query.get_or_404(id)
    if request.method == 'POST':
        employee.name = request.form['name']
        employee.email = request.form['email']
        employee.position = request.form['position']
        
        group_ids = request.form.getlist('group_ids')

        # Clear existing groups
        employee.groups = []

        for group_id in group_ids:
            group = Group.query.get(group_id)
            employee.groups.append(group)

        db.session.commit()
        flash('Employee updated successfully!', 'success')
        return redirect(url_for('add_employee'))
    
    groups = Group.query.all()
    return render_template('add_employee_group.html', employee=employee, groups=groups)

@app.route('/admin/delete_employee/<int:id>', methods=['POST'])
def delete_employee(id):
    employee = Employee.query.get_or_404(id)
    db.session.delete(employee)
    db.session.commit()
    flash('Employee deleted successfully!', 'success')
    return redirect(url_for('employee_list'))

@app.route('/admin/add_group', methods=['GET', 'POST'])
def add_group():
    if request.method == 'POST':
        name = request.form['name']
        
        # Check if the group name already exists
        existing_group = Group.query.filter_by(name=name).first()
        if existing_group:
            flash('Group name already exists!', 'danger')
            return redirect(url_for('add_group'))
        
        new_group = Group(name=name)
        db.session.add(new_group)
        db.session.commit()
        flash('Group created successfully!', 'success')
        return redirect(url_for('list_group'))
    
    return render_template('add_group.html')

@app.route('/admin/delete_group/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    # Find the group by ID
    group = Group.query.get_or_404(group_id)
    
    try:
        db.session.delete(group)
        db.session.commit()
        flash('Group deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting group: {str(e)}', 'danger')
    
    return redirect(url_for('list_group'))

@app.route('/admin/view_group/<int:id>')
def view_group(id):
    group = Group.query.get_or_404(id)
    employees = group.employees  # Access employees through the relationship
    return render_template('view_group.html', group=group, employees=employees)

@app.route('/admintaskdetails/<int:task_id>')
def admintaskdetails(task_id):
    tasks=Task.query.all()
    task = Task.query.get_or_404(task_id)
    assignees = Employee.query.join(TaskAssignee).filter(TaskAssignee.task_id == task_id).all()
    observer = Employee.query.get(task.observer_id)
    
    # Retrieve currently logged-in user from session
    if 'employee_id' in session:
        current_employee_id = session['employee_id']
        current_employee = Employee.query.get(current_employee_id)
        
        # Assuming 'created_by' field of Task model stores username
        created_tasks = Task.query.filter_by(created_by=current_employee.username).all()
        assigned_tasks = Task.query.join(TaskAssignee).filter(TaskAssignee.employee_id == current_employee_id).all()
    else:
        # Handle case where user is not logged in
        created_tasks = []
        assigned_tasks = []
    
    return render_template('admintaskdetails.html', task=task, assignees=assignees, observer=observer, created_tasks=created_tasks, assigned_tasks=assigned_tasks,tasks=tasks)



##########################################  USER AUTH ############################################

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        new_employee = Employee(username=username, password=hashed_password)
        
        try:
            db.session.add(new_employee)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists. Please choose a different one.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        employee = Employee.query.filter_by(username=username).first()
        
        if employee and check_password_hash(employee.password, password):
            session['employee_id'] = employee.id
            session['username'] = employee.username
            flash('Login successful!', 'success')
            return redirect(url_for('userhome'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

"""@app.route('/userhome', methods=['GET', 'POST'])
def userhome():
    if 'username' not in session:
        flash('You are not logged in!', 'warning')
        return redirect(url_for('login'))
    
    employee_id = session['employee_id']
    employee = Employee.query.get_or_404(employee_id)
    
    group_names = ', '.join(group.name for group in employee.groups) if employee.groups else 'No Group'
    
    search_status = request.form.get('search_status', '')
    search_title = request.form.get('search_title', '')

    # Simplifying query to directly fetch Task objects and related observer name
    base_query = db.session.query(Task).outerjoin(Employee, Task.observer_id == Employee.id).add_columns(Employee.name.label('observer_name'))

    if search_status:
        created_tasks = base_query.filter(Task.employee_id == employee_id, Task.status.ilike(f'%{search_status}%')).all()
        assigned_tasks = base_query.join(TaskAssignee, Task.id == TaskAssignee.task_id).filter(TaskAssignee.employee_id == employee_id, Task.status.ilike(f'%{search_status}%')).all()
    elif search_title:
        created_tasks = base_query.filter(Task.employee_id == employee_id, Task.title.ilike(f'%{search_title}%')).all()
        assigned_tasks = base_query.join(TaskAssignee, Task.id == TaskAssignee.task_id).filter(TaskAssignee.employee_id == employee_id, Task.title.ilike(f'%{search_title}%')).all()
    else:
        created_tasks = base_query.filter(Task.employee_id == employee_id).all()
        assigned_tasks = base_query.join(TaskAssignee, Task.id == TaskAssignee.task_id).filter(TaskAssignee.employee_id == employee_id).all()

    task_count = Task.query.filter_by(employee_id=employee_id).count()
    today = datetime.today().date()
    entry = TimeEntry.query.filter_by(employee_id=employee_id, date=today).first() or TimeEntry(total_hours=0)
    events = Event.query.all()
    name = employee.name
    email = employee.email
    position = employee.position
    profile_picture = employee.profile_picture or 'default.png'

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        
        created_by = session.get('employee_id')
        summary = request.form.get('summary')
        status = request.form.get('status')

        if not all([title, description, startdate_str, enddate_str, status, created_by]):
            flash("All fields are required!", 'error')
            return redirect(url_for('userhome'))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            new_task = Task(
                employee_id=employee_id,
                title=title,
                description=description,
                startdate=startdate,
                enddate=enddate,
                created_by=created_by,
                summary=summary,
                status=status,
                observer_id=observer_id,
            )
            db.session.add(new_task)
            db.session.commit()

            for assignee_id in assignees:
                assignee = TaskAssignee(task_id=new_task.id, employee_id=assignee_id)
                db.session.add(assignee)

            db.session.commit()
            flash('Task added successfully!', 'success')
            return redirect(url_for('userhome'))
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'error')
        return redirect(url_for('userhome'))

    employees = Employee.query.all()
    return render_template('userhome.html',
                           events=events, 
                           task_count=task_count, 
                           created_tasks=created_tasks, 
                           assigned_tasks=assigned_tasks, 
                           username=session['username'], 
                           name=name, 
                           email=email, 
                           position=position, 
                           entry=entry, 
                           group_names=group_names,
                           search_status=search_status,
                           search_title=search_title,
                           profile_picture=profile_picture,
                           employee=employee,
                           employees=employees)


@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        flash('You are not logged in!', 'warning')
        return redirect(url_for('login'))

    employee_id = session['employee_id']
    employee = Employee.query.get_or_404(employee_id)

    if 'profile_picture' in request.files:
        profile_picture = request.files['profile_picture']
        if profile_picture.filename != '':
            filename = secure_filename(profile_picture.filename)
            profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(profile_picture_path)
            employee.profile_picture = filename

    db.session.commit()

    return redirect(url_for('userhome'))

@app.route('/update_task/<int:task_id>', methods=['GET', 'POST'])
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        status = request.form.get('status')
        summary = request.form.get('summary')

        if not all([title, description, startdate_str, enddate_str, status]):
            flash("All fields except summary and observer are required!", 'error')
            return redirect(url_for('update_task', task_id=task.id))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            task.title = title
            task.description = description
            task.startdate = startdate
            task.enddate = enddate
            task.status = status
            task.observer_id = observer_id
            task.summary = summary

            # Clear existing assignees and add the new ones
            TaskAssignee.query.filter_by(task_id=task.id).delete()
            for assignee_id in assignees:
                assignee = TaskAssignee(task_id=task.id, employee_id=assignee_id)
                db.session.add(assignee)

            db.session.commit()
            flash('Task updated successfully!', 'success')
            return redirect(url_for('userhome'))
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'error')
        return redirect(url_for('update_task', task_id=task.id))

    employees = Employee.query.all()
    task_assignees = [ta.employee_id for ta in TaskAssignee.query.filter_by(task_id=task.id).all()]

    return render_template('update_task.html', 
                           task=task, 
                           employees=employees, 
                           task_assignees=task_assignees)"""

# Ensure you have a template named 'update_task.html' to render the update form.


@app.route('/usertaskdetails/<int:task_id>')
def usertaskdetails(task_id):
    tasks=Task.query.all()
    task = Task.query.get_or_404(task_id)
    assignees = Employee.query.join(TaskAssignee).filter(TaskAssignee.task_id == task_id).all()
    observer = Employee.query.get(task.observer_id)
    
    # Retrieve currently logged-in user from session
    if 'employee_id' in session:
        current_employee_id = session['employee_id']
        current_employee = Employee.query.get(current_employee_id)
        
        # Assuming 'created_by' field of Task model stores username
        created_tasks = Task.query.filter_by(created_by=current_employee.username).all()
        assigned_tasks = Task.query.join(TaskAssignee).filter(TaskAssignee.employee_id == current_employee_id).all()
    else:
        # Handle case where user is not logged in
        created_tasks = []
        assigned_tasks = []
    
    return render_template('usertaskdetails.html', task=task, assignees=assignees, observer=observer, created_tasks=created_tasks, assigned_tasks=assigned_tasks,tasks=tasks)



@app.route('/logout')
def logout():
    session.pop('employee_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('startpage'))

########################### USER TASK ##############################

"""@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    status_filter = request.args.get('status', '')
    employee_id = session.get('employee_id')

    if not employee_id:
        return "User not logged in", 403

    # Query to get tasks where the employee is either the creator or an assignee
    query = db.session.query(Task, Employee).join(Employee, Task.employee_id == Employee.id).outerjoin(TaskAssignee, TaskAssignee.task_id == Task.id).filter(
        (Task.employee_id == employee_id) | (TaskAssignee.employee_id == employee_id))
    
    if status_filter:
        query = query.filter(Task.status == status_filter)
    
    tasks = query.all()
    task=Task.query.all()
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')  # New line to get observers
        
        created_by = session.get('employee_id')
        summary = request.form.get('summary')
        status = request.form.get('status')

        if not title or not description or not startdate_str or not enddate_str or not status or not created_by:
            return "All fields are required!", 400

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            new_task = Task(
                employee_id=employee_id,
                title=title,
                description=description,
                startdate=startdate,
                enddate=enddate,
                created_by=created_by,
                summary=summary,
                status=status,
                observer_id=observer_id,
            )
            db.session.add(new_task)
            db.session.commit()

            for assignee_id in assignees:
                assignee = TaskAssignee(task_id=new_task.id, employee_id=assignee_id)
                db.session.add(assignee)

            db.session.commit()
            return redirect(url_for('tasks'))
        except ValueError:
            return "Invalid date format. Please use YYYY-MM-DD.", 400
        except Exception as e:
            db.session.rollback()
            return str(e), 500

    employees = Employee.query.all()
    return render_template('userhome.html', tasks=tasks, employees=employees,task=task)"""

@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    try:
        db.session.delete(task)
        db.session.commit()
        return redirect(url_for('userhome'))
    except Exception as e:
        db.session.rollback()
        return str(e), 500

@app.route('/calender')
def calender():
    if 'employee_id' not in session:
        flash('You are not logged in!', 'warning')
        return redirect(url_for('login'))

    events = Event.query.all()
    return render_template('calender.html', events=events)

"""@app.route('/add_event', methods=['POST'])
def add_event():
    title = request.form['title']
    date = request.form['date']
    username = request.form['username']
    
    employee = Employee.query.filter_by(username=username).first()
    if employee:
        new_event = Event(title=title, date=datetime.strptime(date, '%Y-%m-%d'), employee_id=employee.id)
        db.session.add(new_event)
        db.session.commit()
        flash('Event added successfully!', 'success')
    else:
        flash('Employee not found.', 'danger')
    
    return redirect(url_for('userhome'))"""

@app.route('/delete_event/<int:event_id>')
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    db.session.delete(event)
    db.session.commit()
    return redirect(url_for('calender'))



@app.route('/clock_in', methods=['POST'])
def clock_in():
    if 'employee_id' in session:
        employee_id = session['employee_id']
        today = datetime.today().date()
        entry = TimeEntry.query.filter_by(employee_id=employee_id, date=today).first()
        if not entry:
            entry = TimeEntry(employee_id=employee_id, date=today, clock_in=datetime.now())
            db.session.add(entry)
        else:
            entry.clock_in = datetime.now()
        db.session.commit()
        flash('Clocked in!', 'success')
    return redirect(url_for('userhome'))

@app.route('/take_break', methods=['POST'])
def take_break():
    if 'employee_id' in session:
        employee_id = session['employee_id']
        today = datetime.today().date()
        entry = TimeEntry.query.filter_by(employee_id=employee_id, date=today).first()
        if entry:
            entry.break_time = datetime.now()
            db.session.commit()
            flash('Break started!', 'success')
    return redirect(url_for('userhome'))

@app.route('/resume_work', methods=['POST'])
def resume_work():
    if 'employee_id' in session:
        employee_id = session['employee_id']
        today = datetime.today().date()
        entry = TimeEntry.query.filter_by(employee_id=employee_id, date=today).first()
        if entry:
            entry.resume_time = datetime.now()
            db.session.commit()
            flash('Resumed work!', 'success')
    return redirect(url_for('userhome'))

"""@app.route('/clock_out', methods=['POST'])
def clock_out():
    if 'employee_id' in session:
        employee_id = session['employee_id']
        today = datetime.today().date()
        entry = TimeEntry.query.filter_by(employee_id=employee_id, date=today).first()
        if entry:
            entry.clock_out = datetime.now()
            
            # Calculate total hours worked
            if entry.clock_in and entry.clock_out:
                morning_shift = (entry.break_time - entry.clock_in) if entry.break_time else timedelta()
                evening_shift = (entry.clock_out - entry.resume_time) if entry.resume_time else timedelta()
                total_work_time = morning_shift + evening_shift
                entry.total_hours = round(total_work_time.total_seconds() / 3600.0, 2)  # Round to 2 decimal places
            db.session.commit()
            flash('Clocked out!', 'success')
    return redirect(url_for('userhome'))"""


@app.route('/clock_out', methods=['POST'])
def clock_out():
    if 'employee_id' in session:
        employee_id = session['employee_id']
        today = datetime.today().date()
        entry = TimeEntry.query.filter_by(employee_id=employee_id, date=today).first()
        
        if entry:
            entry.clock_out = datetime.now()
            db.session.commit()  # Commit the clock_out time first

            # Calculate total hours worked
            morning_shift = (entry.break_time - entry.clock_in) if entry.break_time else timedelta()
            evening_shift = (entry.clock_out - entry.resume_time) if entry.resume_time else (entry.clock_out - entry.clock_in if entry.clock_in else timedelta())
            total_work_time = morning_shift + evening_shift

            entry.total_hours = round(total_work_time.total_seconds() / 3600.0, 2)  # Round to 2 decimal places
            db.session.commit()

            flash('Clocked out!', 'success')
        else:
            flash('No clock-in record found for today.', 'danger')
    else:
        flash('Employee not logged in.', 'danger')

    return redirect(url_for('userhome'))

@app.route('/working_time', methods=['GET'])
def working_time():
    employee_id = request.args.get('employee_id')
    entry = TimeEntry.query.filter_by(employee_id=employee_id, date=datetime.utcnow().date()).first()
    if entry:
        current_time = datetime.utcnow()
        if entry.resume_time:
            current_working_time = current_time - entry.resume_time
        else:
            current_working_time = timedelta()
        total_seconds = current_working_time.total_seconds()
        total_hours = round(total_seconds / 3600.0, 2)  # Round to 2 decimal places
    else:
        total_hours = 0
    return jsonify(total_hours=total_hours)


"""@app.route('/admin/tasks', methods=['GET', 'POST'])
def admin_tasks():
    if 'username' not in session:
        return "Admin not logged in", 403

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        created_by = session.get('username')
        summary = request.form.get('summary')
        status = request.form.get('status')

        print("Form Data Received:")
        print(f"Title: {title}, Description: {description}, Start Date: {startdate_str}, End Date: {enddate_str}")
        print(f"Assignees: {assignees}, Observer ID: {observer_id}, Created By: {created_by}")
        print(f"Summary: {summary}, Status: {status}")

        if not title or not description or not startdate_str or not enddate_str or not status or not created_by:
            flash("All fields except assignees are required!", "danger")
            return redirect(url_for('admin_tasks'))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            new_task = Task(
                employee_id=created_by,
                title=title,
                description=description,
                startdate=startdate,
                enddate=enddate,
                created_by=created_by,
                summary=summary,
                status=status,
                observer_id=observer_id,
            )
            db.session.add(new_task)
            db.session.commit()

            # Check if task is added
            if new_task.id is None:
                flash("Task creation failed. Please try again.", "danger")
                return redirect(url_for('admin_tasks'))

            print(f"New Task Added: {new_task}")

            # If assignees are provided, add them to the task
            if assignees:
                for assignee_id in assignees:
                    assignee = TaskAssignee(task_id=new_task.id, employee_id=assignee_id)
                    db.session.add(assignee)
                db.session.commit()

            flash("Task created successfully!", "success")
            return redirect(url_for('admintasklist'))
        except ValueError as e:
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
            return redirect(url_for('admintasklist'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('admintasklist'))

    employees = Employee.query.all()
    return render_template('admin_tasks.html', employees=employees)



@app.route('/admin/admin_update_task/<int:task_id>', methods=['GET', 'POST'])
def admin_update_task(task_id):
    if 'user_id' not in session:
        return "Admin not logged in", 403

    task = Task.query.get_or_404(task_id)
    employees = Employee.query.all()  # Assuming you have an Employee model
    current_assignee_ids = [assignee.id for assignee in task.assignees]  # List of current assignee IDs
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        status = request.form.get('status')
        summary = request.form.get('summary')

        if not all([title, description, startdate_str, enddate_str, status]):
            flash("All fields except summary and observer are required!", 'error')
            return redirect(url_for('admin_update_task', task_id=task.id))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            task.title = title
            task.description = description
            task.startdate = startdate
            task.enddate = enddate
            task.status = status
            task.observer_id = observer_id
            task.summary = summary

            TaskAssignee.query.filter_by(task_id=task.id).delete()
            for assignee_id in assignees:
                assignee = TaskAssignee(task_id=task.id, employee_id=assignee_id)
                db.session.add(assignee)

            db.session.commit()
            flash('Task updated successfully!', 'success')
            return redirect(url_for('admintasklist'))
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'error')
        return redirect(url_for('admin_update_task', task_id=task.id))

    return render_template('admin_update_task.html', task=task, employees=employees, current_assignee_ids=current_assignee_ids)"""

    

@app.route('/admin/delete_task/<int:task_id>', methods=['POST'])
def admin_delete_task(task_id):
    if 'user_id' not in session:
        return "Admin not logged in", 403

    task = Task.query.get_or_404(task_id)
    try:
        db.session.delete(task)
        db.session.commit()
        return redirect(url_for('admintasklist'))
    except Exception as e:
        db.session.rollback()
        return str(e), 500


@app.route('/admin/tasks', methods=['GET', 'POST'])
def admin_tasks():
    if 'username' not in session:
        return "Admin not logged in", 403

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        created_by = session.get('username')
        summary = request.form.get('summary')
        status = request.form.get('status')

        if not title or not description or not startdate_str or not enddate_str or not status or not created_by:
            flash("All fields except assignees are required!", "danger")
            return redirect(url_for('admin_tasks'))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            new_task = Task(
                employee_id=created_by,
                title=title,
                description=description,
                startdate=startdate,
                enddate=enddate,
                created_by=created_by,
                summary=summary,
                status=status,
                observer_id=observer_id,
            )
            db.session.add(new_task)
            db.session.commit()

            if new_task.id is None:
                flash("Task creation failed. Please try again.", "danger")
                return redirect(url_for('admin_tasks'))

            assignee_names = []
            if assignees:
                for assignee_id in assignees:
                    assignee = Employee.query.get(assignee_id)
                    if assignee:
                        assignee_names.append(assignee.name)
                        new_task_assignee = TaskAssignee(task_id=new_task.id, employee_id=assignee_id)
                        db.session.add(new_task_assignee)
                db.session.commit()

            observer_name = None
            if observer_id:
                observer = Employee.query.get(observer_id)
                observer_name = observer.name if observer else None

            # Log the action in the feed
            admin_id = session.get('user_id')
            feed_details = f"Assignees: {', '.join(assignee_names)}"
            if observer_name:
                feed_details += f", Observer: {observer_name}"
            feed_entry = FeedEntry(admin_id=admin_id, action=f"Created new task: {title}", details=feed_details)
            db.session.add(feed_entry)
            db.session.commit()

            flash("Task created successfully!", "success")
            return redirect(url_for('admintasklist'))
        except ValueError as e:
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
            return redirect(url_for('admintasklist'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('admintasklist'))

    employees = Employee.query.all()
    return render_template('admin_tasks.html', employees=employees)



@app.route('/admin/admin_update_task/<int:task_id>', methods=['GET', 'POST'])
def admin_update_task(task_id):
    if 'user_id' not in session:
        return "Admin not logged in", 403

    task = Task.query.get_or_404(task_id)
    employees = Employee.query.all()  # Assuming you have an Employee model
    current_assignee_ids = [assignee.id for assignee in task.assignees]  # List of current assignee IDs
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        status = request.form.get('status')
        summary = request.form.get('summary')

        if not all([title, description, startdate_str, enddate_str, status]):
            flash("All fields except summary and observer are required!", 'error')
            return redirect(url_for('admin_update_task', task_id=task.id))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            task.title = title
            task.description = description
            task.startdate = startdate
            task.enddate = enddate
            task.status = status
            task.observer_id = observer_id
            task.summary = summary

            TaskAssignee.query.filter_by(task_id=task.id).delete()
            assignee_names = []
            for assignee_id in assignees:
                assignee = Employee.query.get(assignee_id)
                if assignee:
                    assignee_names.append(assignee.name)
                    new_task_assignee = TaskAssignee(task_id=task.id, employee_id=assignee_id)
                    db.session.add(new_task_assignee)

            observer_name = None
            if observer_id:
                observer = Employee.query.get(observer_id)
                observer_name = observer.name if observer else None

            db.session.commit()

            # Log the action in the feed
            admin_id = session.get('user_id')
            feed_details = f"Assignees: {', '.join(assignee_names)}"
            if observer_name:
                feed_details += f", Observer: {observer_name}"
            feed_entry = FeedEntry(admin_id=admin_id, action=f"Updated task: {title}", details=feed_details)
            db.session.add(feed_entry)
            db.session.commit()

            flash('Task updated successfully!', 'success')
            return redirect(url_for('admintasklist'))
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'error')
        return redirect(url_for('admin_update_task', task_id=task.id))

    return render_template('admin_update_task.html', task=task, employees=employees, current_assignee_ids=current_assignee_ids)


@app.route('/admin/update_employee/<int:id>', methods=['GET', 'POST'])
def update_employee(id):
    employee = Employee.query.get_or_404(id)
    if request.method == 'POST':
        employee.name = request.form['name']
        employee.email = request.form['email']
        employee.position = request.form['position']
        employee.joining_date = datetime.strptime(request.form['joining_date'], '%Y-%m-%d')
        group_ids = request.form.getlist('group_ids')

        # Clear existing groups
        employee.groups = []

        for group_id in group_ids:
            group = Group.query.get(group_id)
            employee.groups.append(group)

        db.session.commit()

        # Log the action in the feed
        admin_id = session.get('user_id')
        feed_entry = FeedEntry(admin_id=admin_id, action=f"Updated employee: {employee.name}")
        db.session.add(feed_entry)
        db.session.commit()

        flash('Employee updated successfully!', 'success')
        return redirect(url_for('employee_list', id=employee.id))

    groups = Group.query.all()
    return render_template('update_employee.html', employee=employee, groups=groups)

@app.route('/admin/add_employee', methods=['GET', 'POST'])
def add_employee():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        position = request.form['position']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        joining_date = datetime.strptime(request.form['joining_date'], '%Y-%m-%d')

        new_employee = Employee(name=name, email=email, position=position, joining_date=joining_date, username=username, password=hashed_password)

        db.session.add(new_employee)
        db.session.commit()

        # Log the action in the feed
        admin_id = session.get('user_id')
        feed_entry = FeedEntry(admin_id=admin_id, action=f"Added new employee: {name}")
        db.session.add(feed_entry)
        db.session.commit()

        flash('Employee added successfully!', 'success')
        return redirect(url_for('employee_list'))

    employees = Employee.query.all()
    groups = Group.query.all()
    return render_template('add_employee.html', groups=groups, employees=employees)

@app.route('/userhome', methods=['GET', 'POST'])
def userhome():
    if 'username' not in session:
        flash('You are not logged in!', 'warning')
        return redirect(url_for('login'))
    
    employee_id = session['employee_id']
    employee = Employee.query.get_or_404(employee_id)
    
    group_names = ', '.join(group.name for group in employee.groups) if employee.groups else 'No Group'
    
    search_status = request.form.get('search_status', '')
    search_title = request.form.get('search_title', '')

    base_query = db.session.query(Task).outerjoin(Employee, Task.observer_id == Employee.id).add_columns(Employee.name.label('observer_name'))

    if search_status:
        created_tasks = base_query.filter(Task.employee_id == employee_id, Task.status.ilike(f'%{search_status}%')).all()
        assigned_tasks = base_query.join(TaskAssignee, Task.id == TaskAssignee.task_id).filter(TaskAssignee.employee_id == employee_id, Task.status.ilike(f'%{search_status}%')).all()
    elif search_title:
        created_tasks = base_query.filter(Task.employee_id == employee_id, Task.title.ilike(f'%{search_title}%')).all()
        assigned_tasks = base_query.join(TaskAssignee, Task.id == TaskAssignee.task_id).filter(TaskAssignee.employee_id == employee_id, Task.title.ilike(f'%{search_title}%')).all()
    else:
        created_tasks = base_query.filter(Task.employee_id == employee_id).all()
        assigned_tasks = base_query.join(TaskAssignee, Task.id == TaskAssignee.task_id).filter(TaskAssignee.employee_id == employee_id).all()

    task_count = Task.query.filter_by(employee_id=employee_id).count()
    today = datetime.today().date()
    entry = TimeEntry.query.filter_by(employee_id=employee_id, date=today).first() or TimeEntry(total_hours=0)
    events = Event.query.all()
    name = employee.name
    email = employee.email
    position = employee.position
    profile_picture = employee.profile_picture or 'default.png'

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        
        created_by = session.get('employee_id')
        summary = request.form.get('summary')
        status = request.form.get('status')

        if not all([title, description, startdate_str, enddate_str, status, created_by]):
            flash("All fields are required!", 'error')
            return redirect(url_for('userhome'))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            new_task = Task(
                employee_id=employee_id,
                title=title,
                description=description,
                startdate=startdate,
                enddate=enddate,
                created_by=created_by,
                summary=summary,
                status=status,
                observer_id=observer_id,
            )
            db.session.add(new_task)
            db.session.commit()

            assignee_names = []
            for assignee_id in assignees:
                assignee = TaskAssignee(task_id=new_task.id, employee_id=assignee_id)
                db.session.add(assignee)
                assignee_names.append(Employee.query.get(assignee_id).name)

            db.session.commit()

            observer_name = Employee.query.get(observer_id).name if observer_id else None

            # Log action
            action = f"Added a new task: {title}"
            details = f"Assignees: {', '.join(assignee_names)}"
            if observer_name:
                details += f", Observer: {observer_name}"
            feed_entry = FeedEntry(employee_id=employee_id, action=action, details=details)
            
            db.session.add(feed_entry)
            db.session.commit()

            flash('Task added successfully!', 'success')
            return redirect(url_for('userhome'))
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'error')
        return redirect(url_for('userhome'))

    employees = Employee.query.all()
    return render_template('userhome.html',
                           events=events, 
                           task_count=task_count, 
                           created_tasks=created_tasks, 
                           assigned_tasks=assigned_tasks, 
                           username=session['username'], 
                           name=name, 
                           email=email, 
                           position=position, 
                           entry=entry, 
                           group_names=group_names,
                           search_status=search_status,
                           search_title=search_title,
                           profile_picture=profile_picture,
                           employee=employee,
                           employees=employees)


@app.route('/update_task/<int:task_id>', methods=['GET', 'POST'])
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        startdate_str = request.form.get('startdate')
        enddate_str = request.form.get('enddate')
        assignees = request.form.getlist('assignees')
        observer_id = request.form.get('observer_id')
        status = request.form.get('status')
        summary = request.form.get('summary')

        if not all([title, description, startdate_str, enddate_str, status]):
            flash("All fields except summary and observer are required!", 'error')
            return redirect(url_for('update_task', task_id=task.id))

        try:
            startdate = datetime.strptime(startdate_str, '%Y-%m-%d').date()
            enddate = datetime.strptime(enddate_str, '%Y-%m-%d').date()

            task.title = title
            task.description = description
            task.startdate = startdate
            task.enddate = enddate
            task.status = status
            task.observer_id = observer_id
            task.summary = summary

            TaskAssignee.query.filter_by(task_id=task.id).delete()
            for assignee_id in assignees:
                assignee = TaskAssignee(task_id=task.id, employee_id=assignee_id)
                db.session.add(assignee)

            db.session.commit()

            # Log action
            action = f"Updated task: {title}"
            feed_entry = FeedEntry(employee_id=session['employee_id'], action=action)
            db.session.add(feed_entry)
            db.session.commit()

            flash('Task updated successfully!', 'success')
            return redirect(url_for('userhome'))
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
        except Exception as e:
            db.session.rollback()
            flash(str(e), 'error')
        return redirect(url_for('update_task', task_id=task.id))

    employees = Employee.query.all()
    task_assignees = [ta.employee_id for ta in TaskAssignee.query.filter_by(task_id=task.id).all()]

    return render_template('update_task.html', 
                           task=task, 
                           employees=employees, 
                           task_assignees=task_assignees)

@app.route('/add_event', methods=['POST'])
def add_event():
    title = request.form['title']
    date = request.form['date']
    username = request.form['username']
    
    employee = Employee.query.filter_by(username=username).first()
    if employee:
        new_event = Event(title=title, date=datetime.strptime(date, '%Y-%m-%d'), employee_id=employee.id)
        db.session.add(new_event)
        db.session.commit()

        # Log action
        action = f"Added an event: {title}"
        feed_entry = FeedEntry(employee_id=employee.id, action=action)
        db.session.add(feed_entry)
        db.session.commit()

        flash('Event added successfully!', 'success')
    else:
        flash('Employee not found.', 'danger')
    
    return redirect(url_for('userhome'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        flash('You are not logged in!', 'warning')
        return redirect(url_for('login'))

    employee_id = session['employee_id']
    employee = Employee.query.get_or_404(employee_id)

    if 'profile_picture' in request.files:
        profile_picture = request.files['profile_picture']
        if profile_picture.filename != '':
            filename = secure_filename(profile_picture.filename)
            profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(profile_picture_path)
            employee.profile_picture = filename

    db.session.commit()

    # Log action
    action = "Updated profile picture"
    feed_entry = FeedEntry(employee_id=employee_id, action=action)
    db.session.add(feed_entry)
    db.session.commit()

    return redirect(url_for('userhome'))


@app.route('/feed', methods=['GET'])
def feed():
    month = request.args.get('month', None)
    if month:
        month_start = datetime.strptime(month, '%Y-%m')
        month_end = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        feed_entries = FeedEntry.query.filter(FeedEntry.timestamp >= month_start, FeedEntry.timestamp <= month_end).order_by(FeedEntry.timestamp.desc()).all()
    else:
        feed_entries = FeedEntry.query.order_by(FeedEntry.timestamp.desc()).all()

    months = [
        {'name': 'January', 'value': '2024-01'},
        {'name': 'February', 'value': '2024-02'},
        {'name': 'March', 'value': '2024-03'},
        {'name': 'April', 'value': '2024-04'},
        {'name': 'May', 'value': '2024-05'},
        {'name': 'June', 'value': '2024-06'},
        {'name': 'July', 'value': '2024-07'},
        {'name': 'August', 'value': '2024-08'},
        {'name': 'September', 'value': '2024-09'},
        {'name': 'October', 'value': '2024-10'},
        {'name': 'November', 'value': '2024-11'},
        {'name': 'December', 'value': '2024-12'},
    ]

    selected_month = month
    return render_template('feed.html', feed_entries=feed_entries, months=months, selected_month=selected_month)




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
