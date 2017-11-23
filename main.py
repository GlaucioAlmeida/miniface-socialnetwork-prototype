#!/usr/bin/env python

from google.appengine.ext.webapp import template
from google.appengine.ext import ndb
from models import Post
from models import Comments
from datetime import date
import logging
import os.path
import webapp2
import string
import re #usar para validar dados IMPORTANTE
from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class Base(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """
	Returns the implementation of the user model.
    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")
  def render(self, view_filename, params):
    path = os.path.join(os.path.dirname(__file__), 'template', view_filename)
    self.response.out.write(template.render(path, params))
	
  def render_view(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user
    params['user'] = user
    username=str(user.auth_ids)
    username=username.split('\'')
    params['username']=username[1]
    path = os.path.join(os.path.dirname(__file__), 'template', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """mostra mensagens simples."""
    params = {
      'message': message
    }
    self.render_view('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)

class Signup(Base):
  def isValidSignup(self,user_name,email,name,last_name,password,password2):
    if re.match(r'^[a-zA-Z0-9._-]+$', user_name) is None:
      return 'Em usuario nao e permitido caracteres especiais'
    if re.match(r'^[a-zA-Z0-9._]+\@[a-zA-Z0-9._]+\.[a-zA-Z]{,}$', email) is None:
      return 'Email invalido!'
    if(filter(lambda x: x in string.punctuation, name))or(filter(lambda x: x in string.punctuation, last_name)):#name e last_name valido?
      return 'Em Nome e Sobrenome nao e permitido caracteres especiais!'
    if len(password)<6:
      return 'Na senha o minimo e de 6 caracteres!'
    if password!=password2:
      return 'Senhas nao conferem!'
    return 'True'

  def get(self):
    self.render_view('signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    last_name = self.request.get('lastname')
    password = self.request.get('password')
    password2 = self.request.get('password2')
    msg=self.isValidSignup(user_name,email,name,last_name,password,password2)
    if msg!='True':
      self.render_view('signup.html',{'msgErro': msg,'user_name':user_name,'email': email,'name': name,'last_name': last_name})
      return

    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,city="nulo",genre=0,birth=date.today(),relationship=0,education="nulo",friends=["nulo"],image="default.jpg",
      email_address=email, name=name, password_raw=password, last_name=last_name, verified=False)
    if not user_data[0]: #user_data e uma tupla
      self.render_view('signup.html', {'msgErro': 'Este usuario/email encontra-se em uso!'})
      return

    user = user_data[1]
    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)
    verification_url = self.uri_for('verification', type='v', user_id=user_id,signup_token=token, _full=True)
    msg = 'Acesse o link abaixo para ativar a conta.<br><br><a href="{url}">{url}</a>'
    self.display_message(msg.format(url=verification_url))

class ForgotPassword(Base):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Usuario nao localizado. (%s)', username)
      self._serve_page(not_found=True)
      return
    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)
    verification_url = self.uri_for('verification', type='p', user_id=user_id,signup_token=token, _full=True)

    msg = 'Acesse o link para redefinir sua senha: <a href="{url}">{url}</a>'
    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    self.render_view('forgot.html', params)


class VerificationHandler(Base):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,'signup')

    if not user:
      logging.info('Nao foi possivel localizar qualquer usuario com ID "%s" Token de Inscricao "%s"',
        user_id, signup_token)
      self.abort(404)
    
    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      self.display_message('<a href="/perfil">Email verificado com sucesso!</a>')
      return
    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_view('resetpassword.html', params)
    else:
      logging.info('Tipo de verificacao nao suportada')
      self.abort(404)

class SetPassword(Base):
  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')
    if not password or password != self.request.get('confirm_password'):
      self.display_message('Senhas nao coincidem')
      return
    user = self.user
    user.set_password(password)
    user.put()
    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    self.display_message('Senha atualizada')

class Login(Base):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      self.redirect(self.uri_for('home'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Falha de login, user: %s Motivo: %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_view('login.html', params)

class Logout(Base):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

class MyPageMural(Base):
	@user_required
	def get(self):
		user = self.user
		postMural = Post.query(Post.userid == user.key).order(-Post.datetime).fetch(15)
		params={}
		params['post']=postMural
		params['user']=user
		self.render('wall.html',params)
	def post(self):
		user = self.user
		username=str(self.user.auth_ids)
		username=username.split('\'')
		message=self.request.get('message')
		newComment=self.request.get('newComment')
		if (message):
			newPost=Post(msg=message,userid=user.key)
			newPost.put();
			self.redirect("/wall")
		else:
			uid=self.request.get('uid')
			if(newComment):
				postMural = ndb.Key(urlsafe=uid).get()
				postMural.comments.append(Comments(msg=newComment,user_name_lastname=user.name+" "+user.last_name,user_auth_ids=username[1]))
				postMural.put()
				self.redirect("/wall")
			else:
				if(uid):
					postMural = ndb.Key(urlsafe=uid).get()
					params={}
					params['params']=postMural
					params['user']=user
					self.render('wall.html',params)

class MyPageAmigos(Base):
	@user_required
	def get(self):
		user = self.user
		youFriend=[]
		newFriend=[]
		params={}
		params['myName']=user.name+" "+user.last_name
		params['myImage']=user.image
		for friend in user.friends:
			friend=friend+"@"
			friend=friend.split('@')
			if(friend[1]=="y"):
				youFriend.append(self.user_model.get_by_auth_id(friend[0]))
			else:
				if(friend[1]=="wait" or friend[1]=="n"):
					newFriend.append(self.user_model.get_by_auth_id(friend[0]))
		params['params']=youFriend
		params['newFriend']=newFriend
		self.render('friends.html',params)

class MyPagePerfil(Base):
	@user_required
	def get(self):
		if(self.request.get('e')=="edit"):
			self.render_template('editaperfil.html')
		else:
			self.render_template('perfil.html')
	def post(self):
		data2=self.request.get('birth')
		data=data2.split('-')
		if(len(data)==3):
			if(int(data[0])>99):
				self.user.birth=date(int(data[0]),int(data[1]),int(data[2]))
			else:
				self.user.birth=date(int(data[2]),int(data[1]),int(data[0]))
		file_content = self.request.POST.multi['imagePerfil'].file.read()
		
		self.user.genre=int(self.request.get('genre'))
		self.user.city=self.request.get('city')
		self.user.relationship=int(self.request.get('relationship'))
		self.user.education=self.request.get('education')
		self.user.put()
		self.render_template('perfil.html')

### CLASSE PRINCIPAL(COMPLEXA) DEFINE AS PAGINAS DO AMIGO
### COMO PERFIL MURAL FOTOS etc DO AMIGO ESPECIFICADO
class AllPagesAmigo(Base):
	def pageFriendsFriend(self,myFriend=None):
		youFriend=[]
		params={}
		params['myFriendName']=myFriend.name+" "+myFriend.last_name
		params['myFriendImage']=myFriend.image
		for friend in myFriend.friends:
			friend=friend+"@"
			friend=friend.split('@')
			if(friend[1]=="y"):
				youFriend.append(self.user_model.get_by_auth_id(friend[0]))
				params['params']=youFriend
		self.render('friendsFriend.html',params)
		
	def get(self, *args, **kwargs):
		#u = self.user_info
		#return self.user_model.get_by_id(u['user_id']) if u else None

		username=str(self.user.auth_ids)
		username=username.split('\'')
		if args[0]==username[1]:
			self.redirect("http://localhost:8081/perfil")
		else:
			myFriend = self.user_model.get_by_auth_id(args[0])
			try:
				myFriend.name==myFriend.name#caso ocorra erro o usuario inserido na url nao existe entao sai do get
			except:
				self.display_message('<a href="/">Esse usuario nao existe!</a>')
				return None
			params={}
			params['params']=myFriend
			params['link']=args[0]
			for friend in myFriend.friends:
				if(friend==username[1]+"@y@"):
					isFriend=0
					break
				else:
					if(friend==username[1]+"@n@"):#nao e amigo aguardando aprovacao
						isFriend=1
					else:
						if(friend==username[1]+"@wait@"):#pedido aguardando aprovacao
							isFriend=2
						else:
							isFriend=3#nao e amigo e nao tem pedido de amizade
			if(isFriend==0):
				if(len(args)==2):
					if(args[1]=='perfil'):
						self.render('perfilFriend.html',params)
					else:
						if(args[1]=='friends'):
							self.pageFriendsFriend(myFriend)#PAGINA AMIGOS DE MEU AMIGO
						else:
							if(args[1]=='wall'):#PAGINA MURAL DE MEU AMIGO
								postMural = Post.query(Post.userid == myFriend.key).order(-Post.datetime).fetch(15)
								params={}
								params['link']=args[0]
								params['post']=postMural
								params['friend']=myFriend
								self.render('wallFriend.html',params)
							else:
								self.abort(404)
				else:#PAGINA PADRAO DEFAULT
					postMural = Post.query(Post.userid == myFriend.key).order(-Post.datetime).fetch(15)
					params={}
					params['link']=args[0]
					params['post']=postMural
					params['friend']=myFriend
					self.render('wallFriend.html',params)#PAGINA PADRAO DEFAULT MURAL DE MEU AMIGO
			else:
				if(isFriend==1):
					self.render('perfilNotFriend1.html',params)#PAGINA PERFIL AMIGO AGUARDANDO APROVACAO
				else:
					if(isFriend==2):
						self.render('perfilNotFriend2.html',params)#AMIGO SOLICITANTE AGUARDANDO APROVACAO
					else:
						self.render('perfilNotFriend3.html',params)#NAO AMIGOS					
	def post(self, *args, **kwargs):
		option = self.request.get('option')
		friend = self.user_model.get_by_auth_id(args[0])
		##ADICAO REMOCAO DE AMIZADES
		if option=="add":#Envia solicitacao de amizade
			username=str(self.user.auth_ids)
			username=username.split('\'')
			friend.friends.append(username[1]+"@wait@")
			friend.put()
			self.user.friends.append(args[0]+"@n@")
			self.user.put()
			self.redirect("/@"+args[0])
		if option=="del":#Cancela solicitacao de amizade
			username=str(self.user.auth_ids)
			username=username.split('\'')
			friend.friends.remove(username[1]+"@wait@")
			friend.put()
			self.user.friends.remove(args[0]+"@n@")
			self.user.put()
			self.redirect("/@"+args[0])
		if option=="remove":#Remove amizade
			username=str(self.user.auth_ids)
			username=username.split('\'')
			friend.friends.remove(username[1]+"@y@")
			friend.put()
			self.user.friends.remove(args[0]+"@y@")
			self.user.put()
			self.redirect("/@"+args[0])
		if option=="rejected":#Amigo rejeita amizade
			username=str(self.user.auth_ids)
			username=username.split('\'')
			friend.friends.remove(username[1]+"@n@")
			friend.put()
			self.user.friends.remove(args[0]+"@wait@")
			self.user.put()
			self.redirect("/@"+args[0])
		if option=="accept":#Amigo aceita amizade
			username=str(self.user.auth_ids)
			username=username.split('\'')
			friend.friends.remove(username[1]+"@n@")
			self.user.friends.remove(args[0]+"@wait@")
			friend.friends.append(username[1]+"@y@")
			self.user.friends.append(args[0]+"@y@")
			friend.put()
			self.user.put()
			self.redirect("/@"+args[0])
		
	####POST DE COMENTARIOS NO MURAL DO AMIGO
		username=str(self.user.auth_ids)
		username=username.split('\'')
		newComment=self.request.get('newComment')
		uid=self.request.get('uid')
		if(newComment):
			postMural = ndb.Key(urlsafe=uid).get()
			postMural.comments.append(Comments(msg=newComment,user_name_lastname=self.user.name+" "+self.user.last_name,user_auth_ids=username[1]))
			postMural.put()
			self.redirect("/@"+args[0]+"/wall")
		else:
			if(uid):
				postMural = ndb.Key(urlsafe=uid).get()
				myFriend = self.user_model.get_by_auth_id(args[0])
				params={}
				params['link']=args[0]
				params['params']=postMural
				params['friend']=myFriend
				self.render('wallFriend.html',params)

class PageMain(Base):##FEED de NOTICIAS(INDEX) PARA FAZER AINDA
  @user_required## if not logged redireciona para /login
  def get(self):
    template_values = {'current_date': 'teste'}
    path = os.path.join(os.path.dirname(__file__)+'/template', 'index.html')
    self.response.out.write(template.render(path, template_values))			

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

app = webapp2.WSGIApplication([
	webapp2.Route( '/@<:\w+>' , AllPagesAmigo, name='AllPagesAmigo'),
	webapp2.Route( '/@<:\w+>/' , AllPagesAmigo, name='AllPagesAmigo'),
	webapp2.Route( '/@<:\w+>/<:\w+>' , AllPagesAmigo, name='AllPagesAmigo'),
	webapp2.Route('/perfil', MyPagePerfil, name='perfil'),
	webapp2.Route('/friends', MyPageAmigos, name='friends'),
	webapp2.Route('/wall', MyPageMural, name='wall'),
	webapp2.Route('/', PageMain, name='home'),
    webapp2.Route('/signup', Signup),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPassword),
    webapp2.Route('/login', Login, name='login'),
    webapp2.Route('/logout', Logout, name='logout'),
    webapp2.Route('/forgot', ForgotPassword, name='forgot'),
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
