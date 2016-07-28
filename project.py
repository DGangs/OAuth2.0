from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_withusers_setup import Base, Restaurant, MenuItem, User

#Imports for web server session management
from flask import session as login_session
import random, string

#Imports for OAuth2
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(open('client_secrets.json','r').read())['web']['client_id']
APPLICATION_NAME = 'Udacity Restaurant Menu Application'

#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
  state=''.join(random.choice(string.ascii_uppercase+string.digits) for x in xrange(32))
  login_session['state']=state
  # return "The current session state is %s" % login_session['state']
  return render_template('login.html', STATE=state)

#Accept Google connection posts for authentication.
@app.route('/gconnect', methods=['POST'])
def gconnect():
  print "Entering gconnect()..."
  #Validate state token.
  if request.args.get('state') != login_session['state']:
    #print "state token check failed..."
    #print "request.args.get('state'): " + request.args.get('state')
    #print "login_session['state']: " + login_session['state']
    response=make_response(json.dumps('Invalid state parameter.'),401)
    response.headers['Content-Type']='application/json'
    return response
  code = request.data
  print "State token verified."
  try:
    #Upgrade the authorization code into a credentials object.
    oauth_flow = flow_from_clientsecrets('client_secrets.json',scope='')
    oauth_flow.redirect_uri='postmessage'
    credentials = oauth_flow.step2_exchange(code)
    print "Upgraded authorization code into a credentials object."
  except FlowExchangeError:
    response = make_response(json.dumps('Failed to upgrade the authorization code.'),401)
    response.headers['Content-Type']='application/json'
    return response
  #Check the access token is valid.
  print "Checking access token is valid..."
  access_token = credentials.access_token
  url=('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
  h = httplib2.Http()
  result = json.loads(h.request(url, 'GET')[1])
  print "Loaded token info..."
  #If there was an error in the access token info, abort.
  if result.get('error') is not None:
    response = make_response(json.dumps(result.get('error')), 500)
    response.headers['Content-Type']='application/json'
    return response
  print "Token info was good."
  #Verify that the access token is used for the intended user.
  gplus_id=credentials.id_token['sub']
  if result['user_id'] != gplus_id:
    response=make_response(json.dumps("Token's user ID doesn't match given user ID."),401)
    response.headers['Content-Type']='application/json'
    return response
  #Verify that the access token is valid for this app.
  if result['issued_to'] != CLIENT_ID:
    response=make_response(json.dumps("Token's client ID doesn't match app's."),401)
    print "Token's client ID doesn't match app's."
    response.headers['Content-Type']='application/json'
    return response
  #Check to see if a user is already logged in.
  stored_credentials=login_session.get('credentials')
  stored_gplus_id=login_session.get('gplus_id')
  if stored_credentials is not None and gplus_id==stored_gplus_id:
    response=make_response(json.dumps("Current user is already connected."),200)
    response.headers['Content-Type']='application/json'
    return response
  #Authentication was successful
  #Store access token in session for later use.
  login_session['credentials']=credentials
  login_session['gplus_id']=gplus_id
  #Get user info.
  userinfo_url="https://www.googleapis.com/oauth2/v1/userinfo"
  params={'access_token':credentials.access_token,'alt':'json'}
  answer=requests.get(userinfo_url,params=params)

  data=answer.json()

  #Store user info in session.
  login_session['provider']='google'
  login_session['username']=data['name']
  login_session['picture']=data['picture']
  login_session['email']=data['email']
  user_id = getUserID(login_session['email'])
  if not user_id: #User email doesn't exist in authentication database - add them.
    user_id=createUser(login_session)
  login_session['user_id']=user_id

  output=''
  output+='<h1>Welcome, '
  output+=login_session['username']
  output+='!</h1>'
  output+='<img src="'
  output+=login_session['picture']
  output+='" style="width:300px;height:300px;border-radius:150px;-webkit-border-radius:150px;-moz-border-radius:150px;">'
  flash("you are now logged in as %s" % login_session['username'])
  print "done!"
  return output


#DISCONNECT - Revoke a current user's token and reset their login_session.
@app.route('/gdisconnect')
def gdisconnect():
  #Only disconnect if a user currently connected.
  credentials=login_session.get('credentials')
  if credentials is None:
    response=make_response(json.dumps('Current user not connected.'),401)
    response.headers['Content-Type']='application/json'
    return response
  #Execute HTTP GET request to revoke current user token.
  access_token=credentials.access_token
  url='https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
  h = httplib2.Http()
  result=h.request(url,'GET')[0]
  #Check result of revoke request:
  if result['status']=='200':
    #Was successful, reset user's session:
    # del login_session['credentials']
    # del login_session['gplus_id']
    # del login_session['username']
    # del login_session['picture']
    # del login_session['email']
    # #response=make_response(json.dumps('Successfully disconnected.'),200)
    # #response.headers['Content-Type']='application/json'
    # #return response
    # flash('Successfully logged out!')
    return redirect(url_for('showRestaurants'))
  else:
    #For some reason token was invalid:
    #Still reset session:
    # if 'credentials' in login_session: del login_session['credentials']
    # if 'gplus_id' in login_session: del login_session['gplus_id']
    # if 'username' in login_session: del login_session['username']
    # if 'picture' in login_session: del login_session['picture']
    # if 'email' in login_session: del login_session['email']
    # #response=make_response(json.dumps('Failed to revoke token for current user.'),400)
    # #response.headers['Content-Type']='application/json'
    # #return response
    # flash('Failed to revoke token for current user.')
    return redirect(url_for('showRestaurants'))


#Accept Facebook connection posts for authentication.
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
  print "Entering fbconnect()..."
  #Validate state token.
  if request.args.get('state') != login_session['state']:
    #print "state token check failed..."
    #print "request.args.get('state'): " + request.args.get('state')
    #print "login_session['state']: " + login_session['state']
    response=make_response(json.dumps('Invalid state parameter.'),401)
    response.headers['Content-Type']='application/json'
    return response
  temp_access_token = request.data #short lived client access token
  print "State token verified."
  #Exchange client token for long-lived server-side token
  app_id = json.loads(open('fb_client_secrets.json','r').read())['web']['app_id']
  app_secret = json.loads(open('fb_client_secrets.json','r').read())['web']['app_secret']
  print "Read client secrets."
  url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, temp_access_token)
  #url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s&redirect_uri=%s' % (app_id, app_secret, access_token,'http://localhost:5000/restaurant')
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]
  print "Requested long-live token."
  try:
    result_json = json.loads(result)
    print "Error found in request: " + result_json['error']['message']
    response = make_response(json.dumps('Failed to upgrade the Facebook client authorization token. ' + result_json['error']['message']),401)
    response.headers['Content-Type']='application/json'
    return response
  except:
    print "Upgraded client token into a long-lived server-side token."

  #Use token to get user info from API, **** never used.
  userinfo_url = 'https://graph.facebook.com/v2.7/me'
  #Strip expire tag from server access token
  print "Facebook token result: " + result
  access_token = (result.split("&")[0]).split("=")[1] #Split from expiration, then drop param name 'access_token=' for long-lived token.
  print "Facebook token: " + access_token

  # #Check the access token is valid.
  # print "Checking access token is valid..."
  # url= 'graph.facebook.com/debug_token?input_token=%s&access_token=%s' % (access_token, app_secret)
  # #h = httplib2.Http() Not needed , redundant from line above
  # result = json.loads(h.request(url, 'GET')[1])
  # print "Loaded debug check of token..."
  # #If there was an error in the access token info, abort.
  # if result.get('error') is not None:
  #   response = make_response(json.dumps(result.get('error')), 500)
  #   response.headers['Content-Type']='application/json'
  #   return response
  # print "Token is good."

  # #Verify that the access token is used for the intended user.
  # gplus_id=credentials.id_token['sub']
  # if result['user_id'] != gplus_id:
  #   response=make_response(json.dumps("Token's user ID doesn't match given user ID."),401)
  #   response.headers['Content-Type']='application/json'
  #   return response

  # #Verify that the access token is valid for this app.
  # if result['issued_to'] != CLIENT_ID:
  #   response=make_response(json.dumps("Token's client ID doesn't match app's."),401)
  #   print "Token's client ID doesn't match app's."
  #   response.headers['Content-Type']='application/json'
  #   return response

  # #Check to see if a user is already logged in.
  # stored_credentials=login_session.get('credentials')
  # stored_gplus_id=login_session.get('gplus_id')
  # if stored_credentials is not None and gplus_id==stored_gplus_id:
  #   response=make_response(json.dumps("Current user is already connected."),200)
  #   response.headers['Content-Type']='application/json'
  #   return response
  # #Authentication was successful

  #Store access token in session for later use.
  #stored_token = token.split("=")[1] #strip out param before equal sign.
  login_session['access_token'] = access_token

  #Get user info.
  url = 'https://graph.facebook.com/v2.7/me?access_token=%s&fields=name,id,email' % access_token #could add location to get zipcode
  #h = httplib2.Http() Not needed , redundant from line above
  data = json.loads(h.request(url, 'GET')[1])
  print data

  #Store user info in session.
  login_session['provider']='facebook'
  login_session['username']=data['name']
  login_session['email']=data['email']
  login_session['facebook_id']=data['id']

  #Get user picture
  url = 'https://graph.facebook.com/v2.7/me/picture?access_token=%s&redirect=0&height=200&width=200' % access_token
  data = json.loads(h.request(url, 'GET')[1])
  login_session['picture'] = data['data']['url']

  #Check if user exists
  user_id = getUserID(login_session['email'])
  if not user_id: #User email doesn't exist in authentication database - add them.
    user_id=createUser(login_session)
  login_session['user_id']=user_id

  output=''
  output+='<h1>Welcome, '
  output+=login_session['username']
  output+='!</h1>'
  output+='<img src="'
  output+=login_session['picture']
  output+='" style="width:300px;height:300px;border-radius:150px;-webkit-border-radius:150px;-moz-border-radius:150px;">'
  flash("you are now logged in as %s" % login_session['username'])
  print "done!"
  return output


#DISCONNECT FACEBOOK- Revoke a current user's token and reset their login_session.
@app.route('/fbdisconnect')
def fbdisconnect():
  #Only disconnect if a user currently connected.
  if 'facebook_id' not in login_session:
    response=make_response(json.dumps('Current user not connected.'),401)
    response.headers['Content-Type']='application/json'
    return response
  facebook_id=login_session['facebook_id']
  #Execute HTTP GET request to revoke current user token.
  access_token=login_session['access_token']
  url='https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
  h = httplib2.Http()
  result=h.request(url,'DELETE')[1]
  # del login_session['facebook_id']
  # del login_session['user_id']
  # del login_session['username']
  # del login_session['picture']
  # del login_session['email']
  # flash('You have been logged out.')
  return redirect(url_for('showRestaurants'))

  # #Check result of revoke request:
  # if result['status']=='200':
  #   #Was successful, reset user's session:
  #   del login_session['credentials']
  #   del login_session['gplus_id']
  #   del login_session['username']
  #   del login_session['picture']
  #   del login_session['email']
  #   #response=make_response(json.dumps('Successfully disconnected.'),200)
  #   #response.headers['Content-Type']='application/json'
  #   #return response
  #   flash('Successfully logged out!')
  #   return redirect(url_for('showRestaurants'))
  # else:
  #   #For some reason token was invalid:
  #   #Still reset session:
  #   if 'credentials' in login_session: del login_session['credentials']
  #   if 'gplus_id' in login_session: del login_session['gplus_id']
  #   if 'username' in login_session: del login_session['username']
  #   if 'picture' in login_session: del login_session['picture']
  #   if 'email' in login_session: del login_session['email']
  #   #response=make_response(json.dumps('Failed to revoke token for current user.'),400)
  #   #response.headers['Content-Type']='application/json'
  #   #return response
  #   flash('Failed to revoke token for current user.')
  #   return redirect(url_for('showRestaurants'))


@app.route('/disconnect')
def disconnect():
  if 'provider' in login_session:
    if login_session['provider'] == 'google':
      gdisconnect()
      del login_session['gplus_id']
      del login_session['credentials']
    if login_session['provider'] == 'facebook':
      fbdisconnect()
      del login_session['facebook_id']

    del login_session['user_id']
    del login_session['username']
    del login_session['picture']
    del login_session['email']
    del login_session['provider']
    flash('You have successfully been logged out.')
    return redirect(url_for('showRestaurants'))
  else:
    flash('You were not logged in.')
    return redirect(url_for('showRestaurants'))

#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  if 'username' not in login_session:
    return render_template('publicrestaurants.html', restaurants = restaurants)
  else:
    user = getUserInfo(login_session['user_id'])
    return render_template('restaurants.html', restaurants = restaurants, user=user)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  #Check if a user is logged in order to add restaurants.
  if 'username' not in login_session:
    #Redirect to login if not.
    return redirect('/login')
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'], user_id = login_session['user_id'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      user = getUserInfo(login_session['user_id'])
      return render_template('newRestaurant.html', user=user)

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  #Check if a user is logged in order to edit restaurants.
  if 'username' not in login_session:
    #Redirect to login if not.
    return redirect('/login')
  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if editedRestaurant.user_id != login_session['user_id']:
    flash('Only the creator can edit their Restaurant.')
    return redirect(url_for('showRestaurants'))
    #return "<script>function myFunction() {alert('You are not authorized to edit this restaurant.  Please create your own restaurant in order to edit it.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    user = getUserInfo(login_session['user_id'])
    return render_template('editRestaurant.html', restaurant = editedRestaurant, user=user)



#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  #Check if a user is logged in order to delete restaurants.
  if 'username' not in login_session:
    #Redirect to login if not.
    return redirect('/login')
  restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if restaurantToDelete.user_id != login_session['user_id']:
    flash('Only the creator can delete their Restaurant.')
    return redirect(url_for('showRestaurants'))
    #return "<script>function myFunction() {alert('You are not authorized to delete this restaurant.  Please create your own restaurant in order to delete it.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
  else:
    user = getUserInfo(login_session['user_id'])
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete, user=user)

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    if 'username' not in login_session:
      return render_template('publicmenu.html', items = items, restaurant = restaurant, creator = creator)
    elif creator.id != login_session['user_id']:
      user = getUserInfo(login_session['user_id'])
      return render_template('usermenu.html', items = items, restaurant = restaurant, creator = creator, user = user)
    else:
      return render_template('menu.html', items = items, restaurant = restaurant, creator = creator, user = creator)


#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  #Check if a user is logged in order to add menu items.
  if 'username' not in login_session:
    #Redirect to login if not.
    return redirect('/login')
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if restaurant.user_id != login_session['user_id']:
    flash('Only the creator can add menu items to their Restaurant.')
    return redirect(url_for('showMenu'))
    #return "<script>function myFunction() {alert('You are not authorized to add menu items to this restaurant.  Please create your own restaurant in order to add menus items.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
      newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id, user_id = restaurant.user_id)
      session.add(newItem)
      session.commit()
      flash('New Menu %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      user = getUserInfo(login_session['user_id'])
      return render_template('newmenuitem.html', restaurant_id = restaurant_id, user=user)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
  #Check if a user is logged in order to edit menu.
  if 'username' not in login_session:
    #Redirect to login if not.
    return redirect('/login')
  editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if restaurant.user_id != login_session['user_id']:
    flash('Only the creator can edit menu items in their Restaurant.')
    return redirect(url_for('showMenu'))
    #return "<script>function myFunction() {alert('You are not authorized to edit menu items in this restaurant.  Please create your own restaurant in order to edit menus items.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
      if request.form['name']:
          editedItem.name = request.form['name']
      if request.form['description']:
          editedItem.description = request.form['description']
      if request.form['price']:
          editedItem.price = request.form['price']
      if request.form['course']:
          editedItem.course = request.form['course']
      session.add(editedItem)
      session.commit() 
      flash('Menu Item Successfully Edited')
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      user = getUserInfo(login_session['user_id'])
      return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem, user=user)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
  #Check if a user is logged in order to delete menu.
  if 'username' not in login_session:
    #Redirect to login if not.
    return redirect('/login')
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one()
  if restaurant.user_id != login_session['user_id']:
    flash('Only the creator can delete menu items in their Restaurant.')
    return redirect(url_for('showMenu'))
    #return "<script>function myFunction() {alert('You are not authorized to delete menu items in this restaurant.  Please create your own restaurant in order to delete menus items.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
      session.delete(itemToDelete)
      session.commit()
      flash('Menu Item Successfully Deleted')
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      user = getUserInfo(login_session['user_id'])
      return render_template('deleteMenuItem.html', item = itemToDelete, user=user)


#Functions to manage users in the authentication database
def getUserID(email):
  try:
    user = session.query(User).filter_by(email = email).one()
    return user.id
  except:
    return None

def getUserInfo(user_id):
  user = session.query(User).filter_by(id = user_id).one()
  return user

def createUser(login_session):
  newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email = login_session['email']).one()
  return user.id

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
