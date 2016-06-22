# Keychain Minder

Keychain Minder is a simple OS X SecurityAgentPlugin for monitoring keychain
password synchronization in enterprise environments.

Ordinarily when users change their login password, OS X will update the login
keychain to match. In enterprise environments, where the password is managed
centrally and synchronized with the machine (via LDAP, AD, etc.) this doesn't
happen. Instead, OS X has a built-in mechanism that appears after authenticating
at the login window to prompt users to update their keychain passwords but many
users don't know what a keychain is, don't understand the dialog or have
forgotten their password.

Keychain Minder re-creates this built-in mechanism but does so for screensaver
and preference pane unlock instead of login. Upon noticing the password
does not work for unlocking the keychain, it will pop-up a dialog informing the
user and giving them the option to either change the password (using both old
and new passwords) or reset the keychain.

## Testing
Keychain Minder is no longer in use at Google and while we will continue to maintain it as best as we can, it will not be as well tested on future OS releases. We will still be responding to issues and pull requests.

Keychain Minder has had very little testing so far but has been known to
work on 10.9.5, 10.10.5 and 10.11.5.

There's no real reason it shouldn't work on 10.7 and 10.8, it just hasn't
been tried. If you find it works, please let us know!

## Screenshots

![Welcome](Docs/KeychainMinderWelcome.png)
![Known Password](Docs/KeychainMinderKnownPw.png)
![Unknown Password](Docs/KeychainMinderUnknownPw.png)

## Installation

There's a package Makefile in the Package folder. You'll need
[The Luggage](https://github.com/unixorn/luggage) installed to build it.

By default the package will install KeychainMinder so that it works at the screensaver.
In order to do this, it has to:
 1. Restore the screensaver login UI to an older-looking UI. SecurityAgentPlugins
    do not run under the newer loginwindow-like UI.
 2. Set the screensaver login policy to `authenticate-session-owner`.

The `update_authdb.py` script has options to change both of these behaviors.

## Uninstallation

`sudo /Library/Security/SecurityAgentPlugins/KeychainMinder.bundle/Contents/Resources/uninstall.sh`

## How it works

During every login the plugin is invoked. It does the following:

1. Check that the right being authenticated is either system.login.screensaver
   or system.preferences.\*
2. Retrieve the username and password currently being authenticated.
3. If both are true, it retrieves the logging in user's default keychain path,
   makes a temporary hardlink to this path, opens the 'new' keychain file
   and attempts to unlock it with the password from 2. It then removes this
   hardlink.
4. Retrieves an array (encoded as a plist) from /Library/Preferences. It either
   adds or removes the currently authenticating user's name from this list
   depending on whether unlocking the keychain in step 3 was successful.

While all of this is happening, launchd is watching the plist file in step 4
for changes and whenever the file is changed, it launches an app embedded in
the plugin. The app does the following:

1. Checks that the currently logged-in user is in the preference file on disk.
   If not, it exits.
2. Displays a simple UI explaining that the keychain password is out of sync
   and asking the user if they remember their previous password.
3a. If the user remembers their password, it asks for both old and new password,
   validates them both and then updates the login keychain password using
   SecKeychainChangePassword. This undocumented function from the Security
   framework will update both the login keychain and Local Items keychain.
3b. If the user does not remember their password, it asks for the new password,
   validates it is the same as their login password and then resets the login
   keychain using this new password using SecKeychainResetLogin. This
   undocumented function from the Security framework will reset both the login
   and Local Items keychains using the provided password.

The hardlink/open/unlock/unlink dance used in both the plugin and UI app
are to avoid locking the Local Items keychain, as doing so can cause issues
when trying to update the password or reset. 

The undocumented functions used to update the password or reset the keychain
could stop working at any time, though the same functions *are* used by Keychain Access.

## Acknowledgements

Thanks to [@tomjburgin](https://twitter.com/tomjburgin) for inspiration and
help getting the plugin working at the screensaver.
