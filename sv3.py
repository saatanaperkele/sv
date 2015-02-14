#!/usr/bin/python
# Copyright (c) 2014, wowaname
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#	list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#	this list of conditions and the following disclaimer in the documentation
#	and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are
# those of the authors and should not be interpreted as representing official
# policies, either expressed or implied, of the FreeBSD Project.

import hashlib
import os
import re
import socket
import sys
from threading import Thread
from getopt import getopt, GetoptError
import time
from binascii import crc32
#from lib import db
from etc.config import *

servers, channels, users, ids = {}, {}, {}, {}
vhosts, vrequests = [], {}
buffer = ""
verbosity, logfile, daemonize, varfile = 0, None, True, False

try:
	options, args = getopt(sys.argv[1:], "dhl:n")
except GetoptError as e:
	print e
	sys.exit(2)

for option, arg in options:
	if option == "-d":
		verbosity = 1
	if option == "-h":
		print "sv IRC services\n"
		print "%s -d -h -l logfile -n\n" % sys.argv[0]
		print "-d\tdebug to stdout"
		print "-h\tthis help"
		print "-l\tdebug to logfile"
		print "-n\tdon't start as daemon"
		sys.exit(0)
	if option == "-l":
		logfile = arg
	if option == "-n":
		# TODO daemonisation
		daemonize = False


class Memo ():
	def __init__ (self, sender, sent, message, read = False):
		self.sender = sender
		self.sent = sent
		self.message = message
		self.read = False

	def read (self):
		self.read = True


class ID ():
	def __init__ (self, username, password_hash, is_admin = 0,
	 notice = True, vhost = None, memos_unread = 0, certfp = ""):
		assert username not in ids
		self.username = username
		self.password = password_hash
		self.permissions = is_admin
		self.notice = notice
		self.vhost = vhost
		self.memos = []
		self.memos_unread = memos_unread
		self.certfp = certfp.split(",")
		debug_line("ID %s created" % username)

	def change_password (self, password):
		self.password = set_password(password)

	def add_memo (self, memo):
		self.memos.append(memo)

	def del_memo (self, memo):
		if memo in self.memos:
			self.memos.remove(memo)
			return 0
		return 1

	def count_unread (self):
		i = 0
		for memo in self.memos:
			i += 0 if memo.read else 1
		return i


class User ():
	def __init__ (self, nick, ident, host, server):
		assert nick not in users
		self.nick = nick
		self.ident = ident
		self.host = host
		self.server = server
		self.channels = {}
		self.mode = ""
		self.id = None
		self.cloakhost = None
		debug_line("User %s created on %s" % (nick, server))

	def toggle_vhost (self, switch):
		if switch and self.get_id_variable("vhost") is not None and self.nick in users:
			debug_line("%s now has vhost %s" % (self.nick,
			 self.get_id_variable("vhost")))
			send_line(":%s METADATA %s cloakhost :%s" %
			 (sv_host, self.nick, self.get_id_variable("vhost")))
			send_line(":%s MODE %s +x" % (sv_host, self.nick))
		else:
			debug_line("restoring host for %s" % (self.nick))
			debug_line("cloakhost: %s, host: %s" % (self.cloakhost, self.host))
			send_line(":%s METADATA %s cloakhost :%s" %
			 (sv_host, self.nick,
			  self.cloakhost if self.cloakhost is not None else self.host))

	def set_cloakhost (self, host, send = True):
		debug_line("%s now has cloakhost %s" % (nick, host))
		self.cloakhost = host
		if send:
			send_line(":%s METADATA %s cloakhost :%s" %
			 (sv_host, self.nick, host))

	def set_ident (self, ident, send = True):
		debug_line("%s now has ident %s" % (nick, ident))
		if send:
			send_line(":%s METADATA %s user :%s" % (sv_host, self.nick, ident))

	#def set_gecos (self, gecos):
	#	self.gecos = gecos

	def set_id (self, id, send = True):
		self.id = ids[id.lower()]
		self.set_ident("^" + id)
		if self.id.vhost is not None:
			self.toggle_vhost(True)
		if send:
			send_line(":%s METADATA %s accountname :%s" %
			 (sv_host, self.nick, id))
		return id

	def get_id_variable (self, variable):
		if self.id is None: return None

		if variable == "username": return self.id.username.lower()
		if variable == "permissions": return self.id.permissions
		if variable == "notice": return self.id.notice
		if variable == "vhost": return self.id.vhost
		if variable == "certfp": return self.id.certfp
		raise SyntaxError("get_id_variable() used incorrectly, variable %s does not exist" % variable)

	def set_id_variable (self, variable, value):
		assert self.id is not None

		if variable == "username": self.id.username = value
		elif variable == "permissions": self.id.permissions = value
		elif variable == "notice": self.id.notice = value
		elif variable == "vhost": self.id.vhost = value
		elif variable == "certfp-append": self.id.certfp.append(value)
		else:
			raise SyntaxError("set_id_variable() used incorrectly, variable %s does not exist" % variable)
		return value

	def join_channel (self, channel):
		assert channel.name not in self.channels
		self.channels[channel.name] = channel

	def part_channel (self, channel):
		assert channel.name in self.channels
		del self.channels[channel.name]

	def change_mode (self, modes):
		add = False
		modelist = set(self.mode)

		for i in modes:
			if i == "+":
				add = True

			elif i == "-":
				add = False

			elif i in "yqaohvVbeI":
				continue

			elif add and i not in modelist:
				modelist.add(i)

			elif not add and i in modelist:
				modelist.discard(i)

		self.mode = "".join(modelist)
		debug_prnt("User %s has modes %s" % (self.nick, self.mode))

	def logout (self):
		self.id = None
		self.toggle_vhost(False)
		self.set_ident(self.ident)

	def __del__ (self):
		for channel in self.channels.keys():
			channels[channel].remove_user(self)

			if not channels[channel].users:
				del channels[channel]

		debug_line("User %s removed" % self.nick)


class Channel ():
	def __init__ (self, name, creator = None):
		assert name not in channels
		self.users = []
		self.name = name
		self.type = name[0]
		self.mode = ""
		self.founder = None
		if creator is not None:
			if creator.id is not None:
				self.founder = creator
		debug_line("Channel %s created" % self.name)

	def add_user (self, user):
		assert user.nick not in self.users
		self.users.append(user.nick)
		user.join_channel(self)
		debug_line("User %s added to channel %s" % (user.nick, self.name))
		return user

	def remove_user (self, user):
		if user.nick in self.users:
			self.users.remove(user.nick)
			user.part_channel(self)
			debug_line("User %s removed from channel %s" % (user.nick,
			 self.name))
			return 0
		return 1

	def change_mode (self, modes):
		add = False
		modelist = set(self.mode)

		for i in modes:
			if i == "+":
				add = True

			elif i == "-":
				add = False

			elif i in "yqaohvVbeI":
				continue

			elif add and i not in modelist:
				modelist.add(i)

			elif not add and i in modelist:
				modelist.discard(i)

		self.mode = "".join(modelist)
		debug_prnt("Channel %s has modes %s" % (self.name, self.mode))

	def __del__ (self):
		debug_line("Channel %s removed" % self.name)


class Server ():
	def __init__ (self, name, id):
		assert name not in servers
		self.name = name
		self.id = int(id)

		debug_line("Server %s (#%d) created" % (name, self.id))

	def __del__ (self):
		for user in users.keys():
			if users[user].server == self.name:
				del users[user]

		debug_line("Server %s removed" % self.name)


def icompare (one, two):
	if type(two) == list:
		return one.lower in [i.lower for i in two]
	else:
		return one.lower() == two.lower()


def parse_msg (message):
	if type(message) == str:
		if message[0] == ":":
			return (message[1:] if len(message) > 1 else "")
		return message
	if message[0][0] == ":":
		message[0] = message[0][1:]
	if len(message) == 1:
		return message[0]
	return " ".join(message)


def get_nick (sender):
	pattern = re.match(r"(.*)!(.*)@(.*)", sender).groups()
	debug_line(pattern)
	return pattern


def find_server (id):
	for server in servers.itervalues():
		if server.id == int(id):
			return server.name


#*DNS			->	abcdefgh.sld.tld/cloak
#*IPv4			->	ab.cd.ef.gh.ip/cloak
# IPv6			->	ab:cd:ef:gh:ij:kl/cloak
# 
# IP on server	->	no-ip/tor/webchat
# 
# Offer			->	unaffiliated/user
# Offer to +B	->	unaffiliated/bot/owner
# sv			->	volatile/bot/sv
# +o			->	volatile/staff/server/lolikaastbgo5dtk.onion
# Helpop		->	volatile/staff/help
#
# For now I think this will mostly be hardcoded.
# the H line in the database will probably have more attributes to account for
# special users: +B, +o, specific servers
def variable_cloak (user):
  #################################################
  # Block for things we shouldn't need to hardcode
	if user.host == "127.0.0.1" and user.server == "UploadDownload.pw":
		return "no-ip/tor/webchat"
  #
  #################################################

	elif user.server == "lolikaastbgo5dtk.onion":
		return None
	elif user.server == "koboijvbwowkcpj2.onion":
		return None
	elif re.match(r"^(?:[0-2]?[0-9]{1,2}\.){3}(?:[0-2]?[0-9]{1,2})$", user.host) is not None:
		# unresolved IP
		mask = re.match(r"^([0-2]?[0-9]{1,2})\.([0-2]?[0-9]{1,2})\.([0-2]?[0-9]{1,2})\.([0-2]?[0-9]{1,2})$", user.host).groups()
		out = ""
		for i in xrange(4):
			out += chr(crc32(mask[i] + str(i)) / 26 % 26 + 97)
			out += chr(crc32(mask[i] + str(i)) % 26 + 97)
			out += "."
		return out + "ip/cloak"
	elif re.match(r"^[-a-zA-Z0-9]*$", user.host) is not None:
		out = ""
		for i in hashlib.md5(user.host).digest()[8:]:
			out += chr(ord(i) % 26 + 97)
		return out + "/cloak"
	elif re.match(r"^[-a-zA-Z0-9]*\.[-a-zA-Z0-9]*$", user.host) is not None:
		mask = re.match(r"([-a-zA-Z0-9])*\.([-a-zA-Z0-9])*", user.host).groups()
		out = ""
		for i in xrange(2):
			for j in hashlib.md5(mask[i]).digest()[8:]:
				out += chr(ord(j) % 26 + 97)
			if i == 0:
				out += "."
		return out + "/cloak"
	elif re.match(r"^(?:[-a-zA-Z0-9]*\.){2,}[-a-zA-Z0-9]*$", user.host) is not None:
		mask = re.match(r"([-a-zA-Z0-9.])*((?:\.[-a-zA-Z0-9]*){2})", user.host).groups()
		out = ""
		for i in hashlib.md5(mask[0]).digest()[8:]:
			out += chr(ord(i) % 26 + 97)
		return out + mask[1] + "/cloak"
	else:
		pass


def debug_prnt (line):
	if verbosity >= 1:
		print "%.1f %s" % (round(time.time(), 1), line)

	if logfile:
		print >> file(logfile, "a"), "%.1f %s" % (round(time.time(), 1), line)


def load_db (file):
	try:
		debug_line("Opening database <%s> for reading" % file)
		timer = time.time()

		for line in open(file):
			arg = line.split()

			# this part of the code wins best eyesore award
			if arg[0] == "ID" and len(arg) == 9:
				ids[arg[1].lower()] = ID(
				 username = arg[1],
				 password_hash = (arg[2], arg[3]),
				 is_admin = int(arg[4]),
				 notice = False if arg[6] == "P" else True,
				 vhost = arg[8],
				 memos_unread = int(arg[5]),
				 certfp = arg[7]
				)
			elif arg[0] == "ID" and len(arg) == 8:
				ids[arg[1].lower()] = ID(arg[1], (arg[2], arg[3]), int(arg[4]),
				 False if arg[6] == "P" else True, None, int(arg[5]), arg[7])
			elif arg[0] == "ID" and len(arg) == 7:
				ids[arg[1].lower()] = ID(arg[1], (arg[2], arg[3]), int(arg[4]),
				 False if arg[6] == "P" else True, None, int(arg[5]), "")
			elif arg[0] == "H" and len(arg) == 2:
				vhosts.append(arg[1])
			elif arg[0] == "HR" and len(arg) == 3:
				vrequests[arg[1]] = arg[2]
			elif arg[0] == "M" and len(arg) == 6:
				ids[arg[1].lower()].add_memo(Memo(arg[2], int(arg[3]), arg[4], bool(arg[5])))
			else:
				debug_line("Line in <%s> cannot be parsed, skipped" % (file))

		debug_line("Database <%s> parsed in %f seconds" %
		 (file, time.time() - timer))

	except IOError:
		debug_line("Database <%s> cannot be opened for writing" % file)

def save_db (file):
	try:
		debug_line("Opening database <%s> for writing" % file)
		timer = time.time()

		with open(file, "w") as fh:
			for id in ids.itervalues():
				fh.write("ID %s %s %s %d %d %c %s%s\n" % (id.username,
				 id.password[0], id.password[1], id.permissions,
				 id.memos_unread, "N" if id.notice else "P",
				 ",".join(id.certfp),
				 " " + id.vhost if id.vhost is not None else ""))
				for memo in id.memos:
					fh.write("M %s %s %d %s %i\n" % (id.username, memo.sender,
					 memo.sent, memo.message, memo.read))
			for vhost in vhosts:
				fh.write("H %s\n" % vhost)
			for nick, request in vrequests.iteritems():
				fh.write("HR %s %s\n" % (nick, request))

		debug_line("Database <%s> written in %f seconds" %
		 (file, time.time() - timer))

	except IOError:
		debug_line("Database <%s> cannot be opened for writing" % file)


def err_line (line):
	debug_prnt("\x1B[33m-!-\x1B[0m %s" % line)

def debug_line (line):
	pass
	debug_prnt("\x1B[34m---\x1B[0m %s" % str(line))

def send_line (line):
	debug_prnt("\x1B[31m<--\x1B[0m %s" % line)
	return sock.send("%s\r\n" % line)

def get_line (line):
	debug_prnt("\x1B[32m-->\x1B[0m %s" % line)


def notice (nick, message = ""):
	send_line(":%s %s %s :%s" % (sv_nick,
	 "PRIVMSG" if users[nick].get_id_variable("notice") == False else "NOTICE",
	 nick, message))


def set_password (password):
	salt = os.urandom(16).encode("base64")[:-1]
	hashed_password = hashlib.sha512(salt + password).hexdigest()
	return (hashed_password, salt)


def check_password (input, salted_password):
	salt = salted_password[1]
	hashed_input = hashlib.sha512(salt + input).hexdigest()
	return hashed_input == salted_password[0]


def logoff (reason, code = 0):
	send_line(":%s QUIT :%s" % (sv_nick, reason))
	save_db(db_file)
	exit(code)


def time_diff (then, now = time.time(), output_format = None):
	difference = now - then
	if output_format == "seconds": return difference
	if output_format == "minutes": return difference/60
	if output_format == "hours": return difference/3600
	if output_format == "days": return difference/86400
	if output_format == "weeks": return difference/604800
	if difference < 60 or output_format == "seconds":
		return "%d seconds" % difference
	if difference < 3600 or output_format == "minutes":
		return "%d minutes" % difference/60
	if difference < 86400 or output_format == "hours":
		return "%d hours" % difference/3600
	if difference < 604800 or output_format == "days":
		return "%d days" % difference/86400
	return "%d weeks" % difference/604800
	# anything past weeks requires knowledge of current month (could be anywhere
	# from 28 to 31 days in a month) and year (leap or not) so let's not worry
	# about that. we care about accuracy


def time_str (t):
	t = time.gmtime(t)
	return "%d-%s%d-%s%d, %s%d:%s%d:%s%d" % (
	 t.tm_year,
	 "" if t.tm_mon > 9 else "0", t.tm_mon,
	 "" if t.tm_mday > 9 else "0", t.tm_mday,
	 "" if t.tm_hour > 9 else "0", t.tm_hour,
	 "" if t.tm_min > 9 else "0", t.tm_min,
	 "" if t.tm_sec > 9 else "0", t.tm_sec
	)


load_db(db_file)
if sv_id not in ids:
	ids[sv_id.lower()] = ID(
	 username = sv_id,
	 password_hash = (None, None),
	 is_admin = 1,
	 notice = True,
	 vhost = sv_vhost,
	 memos_unread = 0,
	 certfp = ""
	)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(uplink)

send_line("PASS %s 0210-IRC+ sv|%s:CLMSX" % (send_password, sv_version))
send_line("SERVER %s 1 :%s" % (sv_host, server_info))
send_line(":%s KILL %s :Make way! Services are linking, and you have my nick." %
 (sv_host, sv_nick))
send_line(":%s SERVICE %s!^%s@%s 1 * %s 1 :%s" % (sv_host, sv_nick, sv_id,
 sv_vhost, sv_modes, sv_gecos))
send_line(":%s NJOIN %s :~%s" % (sv_host, log_channel, sv_nick))


try:
	while True:
		buffer += sock.recv(512)
		data = buffer.split("\r\n")
		buffer = data.pop()

		if not data:
			logoff("Socket closed", 80)

		for line in data:
			get_line(line)
			line = line.split()

			if icompare(line[0], "PING"):
				response = parse_msg(line[1:])
				send_line(":%s PONG %s :%s" % (sv_host, response, response))

			elif len(line) > 1:
				if icompare(line[1], "JOIN"):
					nick = parse_msg(line[0])
					channel = line[2].split("\x07")[0]

					if not channel in channels:
						channels[channel] = Channel(channel, users[nick])

						if users[nick].id:
							send_line(":%s MODE %s +r %s" %
							 (sv_host, channel, users[nick].get_id_variable("username")))

					channels[channel].add_user(users[nick])
					channel_url = "%23" + channel[1:] if channel[0] == "#" else channel
					#send_line(":%s 328 %s %s :%s%s" % (sv_host, nick, channel, base_url + "channel/", channel_url))

				elif icompare(line[1], "NJOIN"):
					channel = line[2]
					nicks = line[3].split(",")

					if not channel in channels:
						channels[channel] = Channel(channel)

					for nick in nicks:
						# TODO dynamic prefixes?
						channels[channel].add_user(users[nick.lstrip(":!~&@%+-")])

				elif icompare(line[1], "CHANINFO"):
					channel = line[2]

					if not channel in channels:
						channels[channel] = Channel(channel)
					
					channels[channel].change_mode(line[3])

				elif icompare(line[1], "MODE"):
					target = line[2]

					if target[0] in "#!+.":
						channels[target].change_mode(line[3])

						if line[3] == "+r" and len(line) == 5:
							channels[target].founder = line[4]
							debug_line("Founder for %s is %s" % (target, line[4]))
					elif target[0] != "&":
						users[target].change_mode(line[3])


				elif icompare(line[1], "PART"):
					nick = parse_msg(line[0])
					channel = line[2]
					channels[channel].remove_user(users[nick])

					if not channels[channel].users:
						del channels[channel]

				elif icompare(line[1], "KICK"):
					nick = line[3]
					channel = line[2]
					channels[channel].remove_user(users[nick])

					if not channels[channel].users:
						del channels[channel]

				elif icompare(line[1], "QUIT"):
					nick = parse_msg(line[0])

					del users[nick]

				elif icompare(line[1], "SQUIT"):
					del servers[line[2]]

				elif icompare(line[1], "SERVER"):
					origin = parse_msg(line[0])
					newserver = line[2]

					servers[newserver] = Server(newserver,
					 int(line[4]) if origin != newserver else 1)

				elif icompare(line[1], "KILL"):
					origin = parse_msg(line[0])
					target = line[2]

					if icompare(target, sv_nick):
						pass
#						send_line(":%s SERVICE %s!%s@%s 1 * %s 1 :%s" %
#						 (sv_host, sv_nick, sv_ident,
#						  sv_vhost, sv_modes, sv_gecos))
					elif origin not in users:
						# KILLs issued by servers
						if users[target].server != origin:
							for channel in users[target].channels.keys():
								channels[channel].remove_user(users[target])

								if not channels[channel].users:
									del channels[channel]

							del users[target]
					elif users[target].server != users[origin].server:
						# local KILLs are followed by a QUIT
						for channel in users[target].channels.keys():
							channels[channel].remove_user(users[target])

							if not channels[channel].users:
								del channels[channel]

						del users[target]

				elif icompare(line[1], "NICK"):
					nick = line[2]

					if len(line) == 3:
						users[parse_msg(nick)] = users.pop(parse_msg(line[0]))
					else:
						server = find_server(line[6])
						ident = line[4]
						host = line[5]
						users[nick] = User(nick, ident, host, server)
						if variable_cloak(users[nick]) is not None and users[nick].cloakhost != variable_cloak(users[nick]):
							# set up a queue, maybe, to allow the parser enough
							# time to run into a METADATA CLOAKHOST if one is
							# supplied? we have a lot of cloakhost conflicts and
							# sv ends up desyncing a bit due to that. not to
							# not to mention there are plenty of avoidable
							# cloakhost changes
							users[nick].set_cloakhost(variable_cloak(users[nick]))
							send_line(":%s MODE %s +x" % (sv_host, nick))

				elif icompare(line[1], "SERVICE"):
					server = find_server(line[3])
					service = get_nick(line[2])
					users[service[0]] = User(service[0], service[1], service[2],
					 server)

				elif icompare(line[1], "METADATA"):
					nick = line[2]
					parameter = parse_msg(line[4:])
					debug_line("Got METADATA %s" % " ".join(line[3:]))

					if icompare(line[3], "accountname") and parse_msg(parameter) in ids:
						users[nick].set_id(parse_msg(parameter))

					elif icompare(line[3], "certfp"):
						users[nick].certfp = parameter
						for id in ids:
							if parameter in ids[id.lower()].certfp:
								users[nick].set_id(id)
								notice(nick, "Automatically identified via certfp.")

					elif icompare(line[3], "cloakhost"):
						users[nick].set_cloakhost(parse_msg(parameter), False)

					elif icompare(line[3], "info"):
						#debug_line("%s now has GECOS %s" % (nick, parameter))
						#users[nick].set_gecos(parse_msg(parameter))
						pass # we don't have a use for GECOS (yet); let the
							 # servers handle it and we'll ignore it

					elif icompare(line[3], "user"):
						users[nick].set_ident(parse_msg(parameter), false)

				elif icompare(line[1], "VERSION"):
					send_line(":%s 351 %s sv-%s %s :" % (sv_host, parse_msg(line[0]), sv_version, sv_host))

				elif icompare(line[1], "WHOIS"):
					origin = parse_msg(line[0])

					send_line(":%s 311 %s %s ^%s %s :%s" % (sv_host, origin, sv_nick, sv_id, sv_vhost, sv_gecos))
					send_line(":%s 312 %s %s %s :%s" % (sv_host, origin, sv_nick, sv_host, server_info))
					send_line(":%s 310 %s %s :is an IRC bot" % (sv_host, origin, sv_nick))
					send_line(":%s 313 %s %s :is an IRC service" % (sv_host, origin, sv_nick))
					send_line(":%s 318 %s %s :End of WHOIS\n" % (sv_host, origin, sv_nick))

				elif icompare(line[1], "LUSERS"):
					origin = parse_msg(line[0])

					send_line(":%s 251 %s :There are %d users on %d servers\n" % (sv_host, origin, len(users), len(servers)))
					send_line(":%s 254 %s :%d channel%s formed\n" % (sv_host, origin, len(channels), "s" if len(channels) != 1 else ""))

				elif icompare(line[1], "MOTD"):
					origin = parse_msg(line[0])
					try:
						send_line(":%s 375 %s :- %s message of the day" % (sv_host, origin, sv_host))

						for line in open("etc/motd"):
							send_line(":%s 372 %s :- %s" % (sv_host, origin, line))

						send_line(":%s 376 %s :End of MOTD command" % (sv_host, origin))

					except IOError:
						send_line(":%s 422 %s :MOTD file is missing" % (sv_host, origin))
						

				elif icompare(line[1], "LIST"):
					origin = parse_msg(line[0])
					for channel in channels.itervalues():
						if "s" in channel.mode:
							send_line(":%s 322 %s * %s :" % (
							 sv_host,
							 origin,
							 len(channel.users),
							))
							continue

						send_line(":%s 322 %s %s %s :%s%s" % (
						 sv_host,
						 origin,
						 channel.name,
						 len(channel.users),
						 "Founder is " if channel.founder else "",
						 channel.founder if channel.founder else ""
						))

					send_line(":%s 323 %s :End of LIST" % (sv_host, origin))

				elif icompare(line[1], "PRIVMSG"):
					nick = parse_msg(line[0])
					command = parse_msg(line[3])

					if icompare(line[2], sv_nick):
						# we're being queried
						if icompare(command, "GLOBAL"):
							if users[nick].get_id_variable("permissions") > 0:
								if len(line) == 4:
									notice(nick, "Message must not be blank.")
								else:
									# parse_msg() will eat this if we don't do it
									if line[4][0] == ":":
										line[4] == ":" + line[4]
									send_line(":%s WALLOPS :(\x02%s\x0F) %s" % (sv_nick, parse_msg(line[0]), parse_msg(line[4:])))
							else:
								notice(nick, "Permission denied.")

						elif icompare(command, "HELP"):
							notice(nick, "\x02-= sv help =-")
							notice(nick)

							if len(line) > 4:
								if icompare(line[4], "HELP"):
									notice(nick, "\x02HELP\x02:")
									notice(nick, "    used for obtaining a list of %s's features or describing certain" % sv_nick)
									notice(nick, "    commands and features")

								elif icompare(line[4], "HOST"):
									notice(nick, "\x02HOST REQUEST vhost\x02:")
									notice(nick, "    request a vhost")

									notice(nick, "\x02HOST LIST\x02:")
									notice(nick, "    list available vhosts")

									notice(nick, "\x02HOST TAKE vhost\x02:")
									notice(nick, "    sets your vhost to one in LIST;")
									notice(nick, "    argument can either be full vhost or index number")
									notice(nick, "    (e.g. \x02TAKE my.special.vhost\x02 or \x02TAKE 2\x02)")

									if users[nick].get_id_variable("permissions"):
										notice(nick, "\x02HOST GIVE username vhost\x02:")
										notice(nick, "    sets a user's vhost")

										notice(nick, "\x02HOST OFFER vhost\x02:")
										notice(nick, "    offer a vhost")

										notice(nick, "\x02HOST ACCEPT username\x02")
										notice(nick, "    accept user's vhost request")

										notice(nick, "\x02HOST DENY username\x02")
										notice(nick, "    deny user's vhost request")

									notice(nick, "\x02HOST ON\x02:")
									notice(nick, "    activate your currently set vhost")

									notice(nick, "\x02HOST OFF\x02:")
									notice(nick, "    restore normal cloaking")

								elif icompare(line[4], "REGISTER"):
									notice(nick, "\x02REGISTER username password\x02:")
									notice(nick, "    registers an account with services under your chosen name and")
									notice(nick, "    secured with a password of your choice. Having a services account")
									notice(nick, "    enables you to take advantage of various features offered by services.")

								elif icompare(line[4], "LOGIN"):
									notice(nick, "\x02LOGIN username password\x02:")
									notice(nick, "    identifies you with an existing services account.")
									notice(nick, "    If you do not have an account, please see the REGISTER command")

								elif icompare(line[4], "MEMO"):
									notice(nick, "\x02MEMO DELETE range\x02:")
									notice(nick, "    deletes memos. range can be a single number (1), range (1-5),")
									notice(nick, "    comma-delimited (1,3), or a combination (1-3,5,6-8). It can also be")
									notice(nick, "    \x02READ\x02 or \x02ALL\x02.")

									notice(nick, "\x02MEMO READ range\x02:")
									notice(nick, "    recalls memos and marks as read. range can be a single number (1),")
									notice(nick, "    range (1-5), comma-delimited (1,3), or a combination (1-3,5,6-8). It can also be")
									notice(nick, "    \x02UNREAD\x02 or \x02ALL\x02.")

									notice(nick, "\x02MEMO SEND username message\x02:")
									notice(nick, "    sends a message to someone else registered with sv")

								elif icompare(line[4], "RESTORE"):
									notice(nick, "\x02RESTORE username code new-password\x02:")
									notice(nick, "    if you have forgotten your password, you can request a code")
									notice(nick, "    be sent to you in order to use this command to create a new")
									notice(nick, "    password for your account.")

								else:
									notice(nick, "\x02%s\x02 is not a command or topic covered by the help system." % line[4])
									notice(nick, "Use \x02/msg %s HELP\x02 for a list of help topics, or" % sv_nick)
									notice(nick, "contact a help operator on the network.")

							else:
								notice(nick, "\x02HELP\x02:")
								notice(nick, "    this help")

								notice(nick, "\x02HOST\x02:")
								notice(nick, "    vhost tools (\x02/msg %s HELP HOST\x02 for subcommands)" % sv_nick)

								notice(nick, "\x02REGISTER username password\x02:")
								notice(nick, "    registers a new username.")

								notice(nick, "\x02LOGIN username password\x02:")
								#notice(nick, "    (also \x02IDENTIFY\x02 and \x02ID\x02)")
								notice(nick, "    identifies you to an existing username")

								notice(nick, "\x02LOGOUT\x02:")
								notice(nick, "    logs you out of your currently identified username")

								notice(nick, "\x02MEMO\x02:")
								notice(nick, "    memo tools (\x02/msg %s HELP MEMO\x02 for subcommands)" % sv_nick)

								notice(nick, "\x02RESTORE username code new-password\x02:")
								notice(nick, "    restores password for username.")
								notice(nick, "    Please ask an operator for the password reset code before using this command.")

								if users[nick].get_id_variable("permissions"):
									notice(nick)
									notice(nick, "\x02GLOBAL message\x02:")
									notice(nick, "    sends a WALLOPS")

									notice(nick, "\x02FREEZE username\x02:")
									notice(nick, "    restricts username")

									notice(nick, "\x02DROP username\x02:")
									notice(nick, "    holds username from being used")

									notice(nick, "\x02DROP username PERMANENT\x02:")
									notice(nick, "    votes for username to be deleted from database, not just marked as dropped")

									notice(nick, "\x02LIST\x02:")
									notice(nick, "    lists registered usernames")

									notice(nick, "\x02RESET password\x02:")
									notice(nick, "    generates a code to give a user to reset their password")

							notice(nick)
							notice(nick, "For additional information on a certain command or topic,")
							notice(nick, "use \x02/msg %s\x0F\x02 HELP command" % sv_nick)
							notice(nick, "\x02-= eof =-")

						elif icompare(command, "MEMO"):
							if len(line) < 5:
								notice(nick, "Insufficient parameters for \x02MEMO\x02. Please")
								notice(nick, "\x02/msg %s\x0F\x02 HELP MEMO\x02 for command help." % sv_nick)

							elif users[nick].id is None:
								notice(nick, "You are not identified.")

							elif icompare(line[4], "READ"):
								if len(line) < 6:
									notice(nick, "Syntax is \x02MEMO READ range\x02 where range")
									notice(nick, "can be a single number (1), range (1-5),")
									notice(nick, "comma-delimited (1,3), or a combination (1-3,5,6-8).")
									notice(nick, "It can also be \x02UNREAD\x02 or \x02ALL\x02.")

								elif icompare(line[5], "UNREAD"):
									for i, memo in enumerate(users[nick].id.memos):
										if memo.read: continue
										notice(nick, "\x02#%d\x0F: On \x02%s\x0F, \x02%s\x0F sent:" % (i, time_str(memo.sent), memo.sender))
										notice(nick, memo.message)
										memo.read = True
									notice(nick, "\x02-= eof =-")
									
								elif icompare(line[5], "ALL"):
									for i, memo in enumerate(users[nick].id.memos):
										notice(nick, "\x02#%d\x0F: On \x02%s\x0F, \x02%s\x0F sent:" % (i, time_str(memo.sent), memo.sender))
										notice(nick, memo.message)
										memo.read = True
									notice(nick, "\x02-= eof =-")

								elif re.match(r"[0-9]+(?:[-,][0-9]+)*", line[5]) is not None:
									for n in line[5].split(","):
										if "-" in n:
											for i in xrange(int(n.split("-")[0]),
											 int(n.split("-")[1]) if int(n.split("-")[1]) < len(users[nick].id.memos) else len(users[nick].id.memos) - 1):
												memo = users[nick].id.memos[i]
												notice(nick, "\x02#%d\x0F: On \x02%s\x0F, \x02%s\x0F sent:" % (i, time_str(memo.sent), memo.sender))
												notice(nick, memo.message)
												memo.read = True
										else:
											if int(n) < len(users[nick].id.memos):
												memo = users[nick].id.memos[int(n)]
												notice(nick, "\x02#%s\x0F: On \x02%s\x0F, \x02%s\x0F sent:" % (n, time_str(memo.sent), memo.sender))
												notice(nick, memo.message)
												memo.read = True
											else:
												notice(nick, "Memo does not exist")
									notice(nick, "\x02-= eof =-")

								else:
									notice(nick, "Invalid range. Range can be a")
									notice(nick, "single number (1), range (1-5),")
									notice(nick, "comma-delimited (1,3), or a combination (1-3,5,6-8).")
									notice(nick, "It can also be \x02UNREAD\x02 or \x02ALL\x02.")

							elif icompare(line[4], "SEND"):
								if len(line) < 6:
									notice(nick, "Syntax is \x02MEMO SEND username message")
								elif line[5] in ids:
									ids[line[5].lower()].add_memo(Memo(nick, time.time(),
									 parse_msg(line[6:])))
									notice(nick, "Memo sent.")
								else:
									notice(nick, "\x02%s\x0F is not registered!" % line[5])
								
							elif icompare(line[4], "DEL"):
								prune = []

								if len(line) < 6:
									notice(nick, "Syntax is \x02MEMO DELETE range\x02 where range")
									notice(nick, "can be a single number (1), range (1-5),")
									notice(nick, "comma-delimited (1,3), or a combination (1-3,5,6-8).")
									notice(nick, "It can also be \x02READ\x02 or \x02ALL\x02.")

								elif icompare(line[5], "READ"):
									for i, __ in enumerate(users[nick].id.memos):
										if not memo.read: continue
										prune.append(i)
									
								elif icompare(line[5], "ALL"):
									users[nick].id.memos = []
									notice(nick, "Deleted \x02%d\x0F memos" % len(users[nick].id.memos))

								elif re.match(r"[0-9]+(?:[-,][0-9]+)*", line[5]) is not None:
									for n in line[5].split(","):
										if "-" in n:
											for i in xrange(int(n.split("-")[0]),
											 int(n.split("-")[1]) if int(n.split("-")[1]) < len(users[nick].id.memos) else len(users[nick].id.memos) - 1):
												prune.append(i)
										else:
											if int(n) < len(users[nick].id.memos):
												prune.append(int(n))
											else:
												notice(nick, "Memo does not exist")
								
								else:
									notice(nick, "Invalid range. Range can be a")
									notice(nick, "single number (1), range (1-5),")
									notice(nick, "comma-delimited (1,3), or a combination (1-3,5,6-8).")
									notice(nick, "It can also be \x02UNREAD\x02 or \x02ALL\x02.")

								for i in prune:
									del users[nick].id.memos[i]

								if len(prune):
									notice(nick, "Deleted \x02%d\x0F memos" % len(prune))

								del prune

							else:
								notice(nick, "Unrecognised command for \x02MEMO\x02. Accepted commands are")
								notice(nick, "\x02SEND READ DELETE\x02.")
								notice(nick, "Please \x02/msg %s\x0F\x02 HELP\x02 for command help." % sv_nick)
		

						elif icompare(command, "HOST"):
							if len(line) < 5:
								notice(nick, "Insufficient parameters for \x02HOST\x02. Please")
								notice(nick, "\x02/msg %s\x0F\x02 HELP HOST\x02 for command help." % sv_nick)

							elif icompare(line[4], "GIVE"):
								if users[nick].get_id_variable("permissions") > 0:
									if line[5] in ids:
										ids[line[5].lower()].vhost = line[6]
										notice(nick, "vhost \x02%s\x0F activated for \x02%s" % (line[6], line[5]))
									else:
										notice(nick, "\x02%s\x0F is not registered!" % line[5])
								else:
									notice(nick, "Permission denied.")

							elif icompare(line[4], "LIST"):
								if len(vhosts):
									notice(nick, "\x02-= HOST LIST =-")
									notice(nick)
									for i, vhost in enumerate(vhosts):
										notice(nick, "[\x02%d\x0F] \x02%s" %
										 (i, vhost))
									notice(nick)
									notice(nick, "\x02-= eof =-")
								else:
									notice(nick, "No vhosts are being offered. \x02/msg %s\x0F\x02 HOST LIST\x02 to" % sv_nick)
									notice(nick, "get a list of vhosts you can choose from, or \x02/msg %s\x0F\x02 HOST REQUEST host" % sv_nick)
									notice(nick, "to request one not on the list.")

							elif icompare(line[4], "OFF"):
								if users[nick].id is not None:
									users[nick].toggle_vhost(False)
									notice(nick, "Normal hostname restored.")
								else:
									notice(nick, "You are not identified.")

							elif icompare(line[4], "OFFER"):
								if users[nick].get_id_variable("permissions") > 0:
									if line[5] in vhosts:
										notice(nick, "vhost \x02%s\x0F is already being offered!")
									else:
										vhosts.append(line[5])
										notice(nick, "vhost offered.")
								else:
									notice(nick, "Permission denied.")

							elif icompare(line[4], "UNOFFER"):
								if users[nick].get_id_variable("permissions") > 0:
									if line[5].isdigit():
										i = int(line[5])
										if i < len(vhosts):
											del vhosts[int(line[5])]
											notice(nick, "vhost removed.")
										else:
											notice(nick, "vhost #\x02%d\x0F wasn't offered!" % i)
									elif line[5] in vhosts:
										vhosts.remove(line[5].lower())
										notice(nick, "vhost removed.")
									else:
										notice(nick, "vhost \x02%s\x0F wasn't offered!" % line[5])
								else:
									notice(nick, "Permission denied.")

							elif icompare(line[4], "ON"):
								if users[nick].id is not None:
									users[nick].toggle_vhost(True)
									notice(nick, "You are now using vhost \x02%s" % users[nick].get_id_variable("vhost"))
								else:
									notice(nick, "You are not identified.")

							elif icompare(line[4], "REQUEST"):
								if users[nick].id is not None:
									vrequests[users[nick].get_id_variable("username")] = line[5]
									send_line(":%s NOTICE %s :vhost \x02%s\x0F requested by \x02%s\x0F (\x02%s\x0F)" % (sv_nick, log_channel, line[5], nick, users[nick].get_id_variable("username")))
									notice(nick, "vhost requested.")
								else:
									notice(nick, "You are not identified.")

							elif icompare(line[4], "ACCEPT"):
								if users[nick].get_id_variable("permissions") > 0:
									if line[5] in vrequests:
										ids[line[5].lower()].vhost = vrequests[line[5]]
										notice(nick, "vhost request accepted.")
										ids[line[5].lower()].add_memo(Memo(nick, time.time(),
										 "Your vhost of \x02%s\x0F was accepted, and will take effect immediately." % vrequests[line[5]]))
										del vrequests[line[5]]
									else:
										notice(nick, "\x02%s\x0F did not request a vhost." % line[5])
								else:
									notice(nick, "Permission denied.")

							elif icompare(line[4], "TAKE"):
								if users[nick].id is None:
									notice(nick, "You are not identified.")
								elif line[5].isdigit():
									i = int(line[5])
									if i < len(vhosts):
										users[nick].set_id_variable("vhost", vhosts[i])
										users[nick].toggle_vhost(True)
										notice(nick, "Your vhost is now \x02%s" % vhosts[i])
									else:
										notice(nick, "vhost #\x02%d\x0F is not being offered. \x02/msg %s\x0F\x02 HOST LIST\x02 to" % (i, sv_nick))
										notice(nick, "get a list of vhosts you can choose from, or \x02/msg %s\x0F\x02 HOST REQUEST host" % sv_nick)
										notice(nick, "to request one not on the list.")
								elif line[5] in vhosts:
									users[nick].set_id_variable("vhost", line[5])
									users[nick].toggle_vhost(True)
									notice(nick, "Your vhost is now \x02%s" % line[5])
								else:
									notice(nick, "vhost \x02%s\x02 is not being offered. \x02/msg %s\x0F\x02 HOST LIST\x02 to" % (line[5], sv_nick))
									notice(nick, "get a list of vhosts you can choose from, or \x02/msg %s\x0F\x02 HOST REQUEST host" % sv_nick)
									notice(nick, "to request one not on the list.")

							else:
								notice(nick, "Unrecognised command for \x02HOST\x02. Accepted commands are")
								notice(nick, "\x02GIVE LIST OFF ON REQUEST TAKE\x02.")
								notice(nick, "Please \x02/msg %s\x0F\x02 HELP HOST\x02 for command help." % sv_nick)

						elif icompare(command, "LOGOUT"):
							if users[nick].id is None:
								notice(nick, "You are not identified.")
							else:
								users[nick].logout()
								notice(nick, "Logged out. Your normal hostname and ident have been restored.")

						elif icompare(command, "REGISTER"):
							if len(line) > 5:
								if line[4].lower() in ids:
									notice(nick, "Account \x02%s\x0F already exists." % line[4])
								else:
									ids[line[4].lower()] = ID(
									 username = line[4],
									 password_hash = set_password(line[5]),
									 is_admin = int("o" in users[nick].mode)
									)
									users[nick].set_id(line[4])
									notice(nick, "Account \x02%s\x0F created." % line[4])
									send_line(":%s NOTICE %s :account registered by \x02%s\x0F (\x02%s\x0F)" % (sv_nick, log_channel, nick, line[4]))
							else:
								notice(nick, "Insufficient parameters for \x02REGISTER\x02. Please")
								notice(nick, "\x02/msg %s\x0F\x02 REGISTER username password\x02 where \x02username\x02 and" % sv_nick)
								notice(nick, "\x02password\x02 are replaced with your desired username and password.")

						#elif icompare(command, ["IDENTIFY", "ID", "LOGIN"]) and len(line) > 5:
						elif icompare(command, "LOGIN"):
							if len(line) > 5:
								if line[4].lower() not in ids:
									notice(nick, "Account \x02%s\x0F is not registered." % line[4])
								elif users[nick].id is not None:
									notice(nick, "You are already identified for this username.")
								elif check_password(line[5], ids[line[4].lower()].password):
									users[nick].set_id(line[4])
									notice(nick, "Identified.")
									if ids[line[4].lower()].memos_unread:
										notice(nick, "You have \x02%d\x0F unread memo%s." % (ids[line[4].lower()].count_unread(), "" if ids[line[4].lower()].count_unread() == 1 else "s"))
								else:
									notice(nick, "Incorrect password.")
							else:
								notice(nick, "Insufficient parameters for \x02LOGIN\x02. Please")
								notice(nick, "\x02/msg %s\x0F\x02 LOGIN username password\x02 where \x02username\x02 and")
								notice(nick, "\x02password\x02 are replaced with the username and password you used to register.")

						elif icompare(command, "SET"):
							if len(line) > 4:
								if icompare(line[4], "NOTICE"):
									if len(line) == 6:
										if icompare(line[5], "ON"):
											users[nick].set_id_variable("notice", True)
											notice(nick, "I will now NOTICE you.")
										elif icompare(line[5], "OFF"):
											users[nick].set_id_variable("notice", False)
											notice(nick, "I will now PRIVMSG you.")
										else:
											notice(nick, "Syntax is \x02SET NOTICE on/off")
									else:
										notice(nick, "Current NOTICE setting: \x02%s" %
										 "on (NOTICE)" if users[nick].get_id_variable("notice") else "off (PRIVMSG)")
								elif icompare(line[4], "CONTACT"):
									notice(nick, "TODO")
								elif icompare(line[4], "PASSWORD"):
									if len(line) == 7:
										if check_password(line[5], users[nick].id.password):
											users[nick].id.change_password(line[6])
											notice(nick, "Password changed successfully.")
										else:
											notice(nick, "Incorrect password.")
									else:
										notice(nick, "Syntax is \x02SET PASSWORD old new")
								elif icompare(line[4], "MAXMEMOS"):
									notice(nick, "TODO")
								elif icompare(line[4], "MEMOFWD"):
									notice(nick, "TODO")
								else:
									notice(nick, "Unrecognised command for \x02SET\x02. Accepted commands are")
									notice(nick, "\x02NOTICE CONTACT PASSWORD MAXMEMOS MEMOFWD\x02.")
									notice(nick, "Please \x02/msg %s\x0F\x02 HELP SET\x02 for command help." % sv_nick)
							else:
								notice(nick, "Insufficient parameters for \x02SET\x02. Please")
								notice(nick, "\x02/msg %s\x0F\x02 HELP SET\x02 for command help." % sv_nick)

						elif icompare(command, "ALLOW"):
							if users[nick].id is None:
								notice(nick, "You are not identified.")

							elif len(line) > 4:
								if icompare(line[4], "ADD"):
									if len(line) > 5:
										if icompare(line[5], "HOST"):
											notice(nick, "TODO")

										elif icompare(line[5], "CERTFP"):
											if users[nick].get_id_variable("certfp") is None:
												notice(nick, "You are not using a client certificate.")
												
											if users[nick].certfp in users[nick].get_id_variable("certfp"):
												notice(nick, "This fingerprint is already accepted.")

											elif len(line) == 6:
												users[nick].set_id_variable("certfp-append", users[nick].certfp)
												notice(nick, "Fingerprint \x02%s\x0F added." % users[nick].certfp)

								elif icompare(line[4], "LIST"):
									if icompare(line[5], "HOST") or len(line) <= 5:
										pass

									if icompare(line[5], "CERTFP") or len(line) <= 5:
										for item in users[nick].get_id_variable("certfp"):
											notice(nick, "Certificate fingerprint \x02%s")

									notice(nick, "\x02-= eof =-")

							else:
								notice(nick, "Unrecognised command for \x02ALLOW\x02. Accepted commands are")
								notice(nick, "\x02ADD DEL LIST PLAIN\x02.")
								notice(nick, "Please \x02/msg %s\x0F\x02 HELP ALLOW\x02 for command help." % sv_nick)

						elif icompare(command, "TRANSFER"):
							if len(line) > 5:
								if line[4][0] == "#" and line[5] in users:
									if users[nick].id is None:
										notice(nick, "You are not identified.")
									elif users[line[5]].id is None:
										notice(nick, "\x02%s\x0F is not identified." % line[5])
									elif users[nick].get_id_variable("username") != channels[line[4]].founder:
										notice(nick, "You aren't founder of \x02%s\x0F!" % line[4])
									else:
										send_line(":%s JOIN :%s" % (sv_nick, line[4]))
										send_line(":%s MODE %s +yr %s %s" % (sv_host, line[4], sv_nick, users[line[5]].get_id_variable("username")))
										send_line(":%s INVITE %s %s" % (sv_nick, line[5], line[4]))
										send_line(":%s NOTICE %s :I'm just stopping by to TRANSFER ownership of \x02%s\x0F from \x02%s\x0F to \x02%s" % (sv_nick, line[4], line[4], nick, line[5]))
										send_line(":%s PART %s :See ya!" % (sv_nick, line[4]))
							else:
								notice(nick, "Insufficient parameters for \x02TRANSFER\x02. Please")
								notice(nick, "\x02/msg %s\x0F\x02 HELP TRANSFER\x02 for command help." % sv_nick)

						elif icompare(command, "WHY"):
							if len(line) > 4:
								if line[4] not in channels:
									notice(nick, "WHY - %s does not exist" % line[4])
								elif users[nick].get_id_variable("username") == channels[line[4]].founder:
									notice(nick, "WHY + %s You are founder (+r)" % line[4])
								else:
									notice(nick, "WHY - %s You must be founder (+r) to use this command." % line[4])
							else:
								notice(nick, "\x02WHY\x02 is primarily a command for channel bots. Please")
								notice(nick, "\x02/msg %s\x0F\x02 HELP WHY\x02 for command help." % sv_nick)

						else:
							notice(nick, "Unrecognised command or incorrect syntax. Please \x02/msg %s\x0F\x02 HELP\x02 for command help." % sv_nick)

					else:
						# we're either getting fantasy commands or someone's
						# talking in the logging channel
						pass

except KeyboardInterrupt:
	logoff("Interrupted", 70)

except AssertionError:
	type, e, tb = sys.exc_info()
	filename = tb.tb_frame.f_code.co_filename
	lineno = tb.tb_lineno
	print "AssertionError in %s, %d: %s" % (filename, lineno, e)
	err_line("\x1B[1mAssertionError in %s, %d:\x1B[0m %s" %
	 (filename, lineno, e))
	logoff("Assertion error (bug)", 100)

except SyntaxError:
	type, e, tb = sys.exc_info()
	filename = tb.tb_frame.f_code.co_filename
	lineno = tb.tb_lineno
	print "SyntaxError in %s, %d: %s" % (filename, lineno, e)
	err_line("\x1B[1mSyntaxError in %s, %d:\x1B[0m %s" % (filename, lineno, e))
	logoff("Syntax error (bug)", 100)

except BaseException:
	type, e, tb = sys.exc_info()
	filename = tb.tb_frame.f_code.co_filename
	lineno = tb.tb_lineno
	print "%s error in %s, %d: %s" % (type, filename, lineno, e)
	err_line("\x1B[1m%s error in %s, %d:\x1B[0m %s" %
	 (type, filename, lineno, e))
	logoff("Uncaught exception (bug)", 100)