import time
import webapp2_extras.appengine.auth.models
from google.appengine.ext import ndb
from webapp2_extras import security

class User(webapp2_extras.appengine.auth.models.User):
  image=ndb.StringProperty()
  birth=ndb.DateProperty()
  genre=ndb.IntegerProperty()
  city=ndb.StringProperty()
  relationship=ndb.IntegerProperty()
  education=ndb.StringProperty()
  friends = ndb.StringProperty(repeated=True)
  
  def set_password(self, raw_password):
    self.password = security.generate_password_hash(raw_password, length=12)

  @classmethod
  def get_by_auth_token(cls, user_id, token, subject='auth'):
    token_key = cls.token_model.get_key(user_id, subject, token)
    user_key = ndb.Key(cls, user_id)
    valid_token, user = ndb.get_multi([token_key, user_key])
    if valid_token and user:
        timestamp = int(time.mktime(valid_token.created.timetuple()))
        return user, timestamp

    return None, None

class Comments(ndb.Model):
	msg = ndb.StringProperty(required = True)
	user_name_lastname = ndb.StringProperty(required = True)
	user_auth_ids=ndb.StringProperty(required = True)
	
class Post(ndb.Model):
	msg = ndb.StringProperty(required = True)
	photo = ndb.StringProperty(required = False)
	datetime = ndb.DateTimeProperty(auto_now_add = True)
	userid = ndb.KeyProperty(required = True)
	comments = ndb.StructuredProperty(Comments,required = False,repeated=True)
	