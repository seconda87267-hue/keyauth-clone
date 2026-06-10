from fastapi import APIRouter, Request, Depends, HTTPException, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import User
from config import FOUNDER_KEY, SECRET_KEY, JWT_ALGORITHM
from datetime import datetime, timedelta
from jose import jwt

router = APIRouter(prefix="/founder", tags=["founder"])


# Helper to verify founder session
def get_founder(request: Request):
    token = request.cookies.get("founder_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("type") == "founder":
            return payload
    except Exception:
        pass
    return None


# Founder login page
@router.get("/login", response_class=HTMLResponse)
def founder_login_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Founder Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: Arial, sans-serif; 
            background: hsl(0, 0%, 3%); 
            color: hsl(0, 0%, 96%);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container { 
            background: hsl(0, 0%, 6%); 
            border: 1px solid hsla(0, 0%, 100%, 0.06);
            border-radius: 16px;
            padding: 40px;
            width: 400px;
        }
        h1 { 
            text-align: center;
            margin-bottom: 30px;
            background: linear-gradient(135deg, hsl(0, 72%, 51%), hsl(43, 74%, 49%));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .form-group { margin-bottom: 20px; }
        label { 
            display: block; 
            color: hsl(0, 0%, 45%); 
            font-weight: bold; 
            font-size: 12px; 
            text-transform: uppercase; 
            letter-spacing: 1.5px;
            margin-bottom: 8px;
        }
        input[type="password"] { 
            width: 100%; 
            padding: 12px; 
            background: hsla(0, 0%, 0%, 0.4); 
            border: 1px solid hsla(0, 0%, 100%, 0.06);
            border-radius: 10px;
            color: hsl(0, 0%, 96%);
            font-size: 14px;
        }
        input:focus { 
            outline: none;
            border-color: hsla(0, 72%, 51%, 0.5);
            box-shadow: 0 0 0 3px hsla(0, 72%, 51%, 0.1);
        }
        button { 
            width: 100%;
            background: linear-gradient(135deg, hsl(0, 72%, 51%), hsl(0, 65%, 40%));
            color: white;
            padding: 14px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        button:hover { transform: translateY(-2px); }
        .back-link { text-align: center; margin-top: 20px; }
        .back-link a { color: hsl(43, 74%, 49%); text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>👑 FOUNDER LOGIN</h1>
        <form method="post">
            <div class="form-group">
                <label>Founder Key</label>
                <input type="password" name="founder_key" required placeholder="Enter Founder Key">
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="back-link">
            <a href="/admin/login">← Back to Admin Login</a>
        </div>
    </div>
</body>
</html>
    """


# Founder login
@router.post("/login")
def founder_login(founder_key: str = Form(...)):
    if founder_key != FOUNDER_KEY:
        raise HTTPException(status_code=401, detail="Invalid founder key")
    
    # Create JWT token valid for 24 hours
    token = jwt.encode(
        {"type": "founder", "exp": datetime.utcnow() + timedelta(hours=24)},
        SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )
    response = RedirectResponse(url="/founder/dashboard", status_code=303)
    response.set_cookie("founder_token", token, httponly=True, max_age=86400, samesite="lax")
    return response


# Founder dashboard
@router.get("/dashboard", response_class=HTMLResponse)
def founder_dashboard(request: Request, db: Session = Depends(get_db)):
    founder = get_founder(request)
    if not founder:
        return RedirectResponse(url="/founder/login", status_code=303)
    
    admins = db.query(User).filter(User.role == "admin").all()
    admins_html = ""
    for admin in admins:
        admins_html += f"""
        <tr>
            <td>{admin.id}</td>
            <td>{admin.username}</td>
            <td>{admin.created_at if admin.created_at else 'N/A'}</td>
            <td>
                <form method="post" action="/founder/delete-admin/{admin.id}" style="display: inline;">
                    <button type="submit" onclick="return confirm('Are you sure?')" style="background: hsl(0, 72%, 51%); color: white; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer;">Delete</button>
                </form>
            </td>
        </tr>
        """
    
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Founder Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: Arial, sans-serif; 
            background: hsl(0, 0%, 3%); 
            color: hsl(0, 0%, 96%);
            padding: 40px;
        }}
        .container {{ 
            max-width: 1000px; 
            margin: 0 auto; 
            background: hsl(0, 0%, 6%); 
            border: 1px solid hsla(0, 0%, 100%, 0.06);
            border-radius: 16px;
            padding: 40px;
        }}
        h1 {{ 
            text-align: center;
            margin-bottom: 40px;
            background: linear-gradient(135deg, hsl(0, 72%, 51%), hsl(43, 74%, 49%));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ 
            color: hsl(43, 74%, 49%);
            border-bottom: 2px solid hsl(43, 74%, 49%);
            padding-bottom: 10px;
            margin-bottom: 20px;
            text-transform: uppercase;
            font-size: 18px;
            letter-spacing: 2px;
        }}
        .form-group {{ margin-bottom: 15px; }}
        label {{ 
            display: block; 
            color: hsl(0, 0%, 45%); 
            font-weight: bold; 
            font-size: 12px; 
            text-transform: uppercase; 
            letter-spacing: 1.5px;
            margin-bottom: 8px;
        }}
        input {{ 
            width: 100%; 
            padding: 12px; 
            background: hsla(0, 0%, 0%, 0.4); 
            border: 1px solid hsla(0, 0%, 100%, 0.06);
            border-radius: 10px;
            color: hsl(0, 0%, 96%);
            font-size: 14px;
        }}
        input:focus {{ 
            outline: none;
            border-color: hsla(0, 72%, 51%, 0.5);
            box-shadow: 0 0 0 3px hsla(0, 72%, 51%, 0.1);
        }}
        button {{ 
            background: linear-gradient(135deg, hsl(0, 72%, 51%), hsl(0, 65%, 40%));
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }}
        button:hover {{ transform: translateY(-2px); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid hsla(0, 0%, 100%, 0.06); }}
        th {{ 
            background: hsla(0, 0%, 6%); color: hsl(43, 74%, 49%); font-weight: bold; font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; }}
        .logout {{ text-align: right; margin-bottom: 20px; }}
        .logout a {{ color: hsl(0, 72%, 51%); text-decoration: none; font-weight: bold; }}
        .back {{ text-align: left; margin-bottom: 20px; }}
        .back a {{ color: hsl(43, 74%, 49%); text-decoration: none; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logout">
            <a href="/founder/logout">Logout</a>
        </div>
        <h1>👑 FOUNDER DASHBOARD</h1>
        
        <div class="back">
            <a href="/admin/login">← Back to Admin Login</a>
        </div>
        
        <!-- Add New Admin -->
        <div class="section">
            <h2>➕ CREATE NEW ADMIN</h2>
            <form method="post" action="/founder/create-admin">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required placeholder="Enter admin username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="Enter admin password">
                </div>
                <button type="submit">Create Admin</button>
            </form>
        </div>
        
        <!-- List Existing Admins -->
        <div class="section">
            <h2>📋 EXISTING ADMINS</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Created At</th>
                    <th>Action</th>
                </tr>
                {admins_html}
            </table>
        </div>
    </div>
</body>
</html>
    """


# Create new admin
@router.post("/create-admin")
def create_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    founder = get_founder(request)
    if not founder:
        return RedirectResponse(url="/founder/login", status_code=303)
    
    # Check if username already exists
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    new_admin = User(username=username, password_hash=password, role="admin")
    db.add(new_admin)
    db.commit()
    
    return RedirectResponse(url="/founder/dashboard", status_code=303)


# Delete admin
@router.post("/delete-admin/{admin_id}")
def delete_admin(
    request: Request,
    admin_id: int,
    db: Session = Depends(get_db)
):
    founder = get_founder(request)
    if not founder:
        return RedirectResponse(url="/founder/login", status_code=303)
    
    admin = db.query(User).filter(User.id == admin_id, User.role == "admin").first()
    if admin:
        db.delete(admin)
        db.commit()
    
    return RedirectResponse(url="/founder/dashboard", status_code=303)


# Founder logout
@router.get("/logout")
def founder_logout():
    response = RedirectResponse(url="/founder/login", status_code=303)
    response.delete_cookie("founder_token")
    return response
