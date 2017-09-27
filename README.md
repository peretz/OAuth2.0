# Authentication & Authorization: OAuth Project - Implement security features for a restaurant and menu management app.

This project is based on Udacity's Authentication & Authorization: OAuth project. The objective
of this project is learning the basic concepts around a secure website, which includes:

* Difference between *Authentication and Authorization*.
* Pros and cons of third party OAuth providers.
* Familirity with the following concepts: *Hashing, encryption, man-in-the-middle attacks and anti forgery state token*.
* Protocols for OAuth usage such as *Google Plus Hybrid Auth flow*.
* Website visibility depending on user login permissions (Local Permission System).

In order to learn these concepts, the project implements a the user login for a restaurants and menu
management app. The login is implemented using Google Plus and Facebook as third party OAuth providers.

## File structure.

There are four files:

* *database_setup.py:* Defines the database objects.
* *lotsofmenuswithuser.py:* Contains restaurants and menus to create in the database and the respective user that created them.
* *project.py:* Contains server-side communication to use Google Plus and Facebook OAuth providers.
* *login.html:* Contains client-side communication to use Google Plus and Facebook OAuth providers.

## Setup code and run website.

1. Access the vagrant environment
2. Run database_setup.py to create the database
3. Run lotsofmenuswithuser.py to populate the database
4. Add your Google Plus's Client ID to login.html, and download the client_secrets.json file linked to your account.
5. Add your Facebook's Application ID and latest API version to your login.html, and create a JSON file called fb_client_secrets.json with the following fields
{
    "web": {
        "app_id": {your-facebook-app-id},
        "app_secret": {your-facebook-app-secret}
    }
}        

6. Run project.py and navigate to localhost:5000 in your browser

If you ran successfully the previous steps, you should be able to:
* See a complete list of all restaurants.
* Access the menu for a specific restaurant.
* Login in to the website using Google Plus or Facebook as OAutho provider.
* Create, edit and delete a restaurant when the correct user is logged in.
* Create, edit and delete items in the menu when the correct user is logged in.
