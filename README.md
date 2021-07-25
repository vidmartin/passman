
# passman

passman is a command-line password manager written in Rust, storing passwords securely in local files.

## basic usage

passman allows you to create multiple `profiles` - each profile stores any amount of passwords under a single profile-level password.
To create a profile, run:

    passman add-profile [name of profile]

You will be prompted to enter the password for your new profile. After that, you can add new key-value pairs into the profile by running:

    passman set [path to value]

Here, `[path to value]` specifies the name of the profile and the key of the value to be set in the format `[profile name].[value key]`.
If the path doesn't contain a `.`, it will be interpreted as the key of a value in the `default` profile.

After running this command, you will be prompted to enter the password for the profile you're trying to access, and then you can
enter the desired value for the given key.

After a value was set, you can read it by running:

    passman get [path to value]

This will prompt you to enter the password for the profile, and then print the value stored under the specified key. After you press
any key, the displayed value should dissappear.

## all commands

- `passman add-profile [name of profile]`
create a profile with the given name

- `passman del-profile [name of profile]`
delete the profile with the given name

- `passman copy-profile [name of source profile] [name of new profile]`
create a new profile, copying the contents and password of the source profile into it.

- `passman set-profile-password [name of profile]`
prompts the user to enter a new password for the specified profile, and
then changes the password accordingly (decrypting the associated file and
then re-encrypting it using the new password)

- `passman get [path to value]`
prints the name of the given value

- `passman set [path to value]`
sets the given key in the given profile to the value entered by user

- `passman del [path to value]`
removes the specified key from the specified profile

- `passman list`
prints the names of all profiles

- `passman list [name of profile]`
after the user enters the password for the given profile, prints
the keys of all values stored inside of that profile.