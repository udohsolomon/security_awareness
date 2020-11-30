# Broken Authentication Flaws in JavaScript

## Description

Attackers will try to break into authentication components such as cookies, sessions, and tokens to be able to impersonate other users or perform horizontal and lateral movements (for instance accessing a feature that is just enabled for an administrator role).

Flaws in authentication mechanisms involve weak password policies, storing credentials in plain text in the databases, improper session expiration (and timeouts), security questions, account updates and so on

## Vulnerable Code Example

Storing passwords in plain text in a database is a security risk that could allow an attacker to get access to other user accounts. The following code is an example of incorrect password storage:

```node

router.post('/register-user', function(req, res, next){    
    
    //input data validations 
    req.assert('name'    , 'Name is required').notEmpty()          
    req.assert('password', 'Password is required').notEmpty()   
    req.assert('email'   , 'A valid email is required').isEmail()  
    
    var errors = req.validationErrors()
    if( !errors ) { 
        var user = {
            name       : req.sanitize('name').escape().trim(),
            email      : req.sanitize('email').escape().trim(),
            password   : req.sanitize('password').escape().trim()
        }
        connection.query('INSERT INTO users SET ?', user, function(err, result) {
            if (err) {
            req.flash('error', err)
            res.render('auth/register', {
                title: 'Registration Page',
                name: '',
                password: '',
                email: ''                    
            })
            } else {                
                req.flash('success', 'You have successfully signup!');
                res.redirect('/login');
            }
        });
    }
});
```
This code, although seems to perform a correct input data validation (you can tell it because request parameters are sanitized and escaped), is storing the password in clear text in the database without doing any sort of hashing.

## Mitigation

A more secure implementation would be like using an industry-standard password hashing algorithm such as *bcrypt*. Following code shows a better implementation:

```node

router.post('/register-user', function(req, res, next){    
    
    //input data validations 
    req.assert('name'    , 'Name is required').notEmpty()          
    req.assert('password', 'Password is required').notEmpty()   
    req.assert('email'   , 'A valid email is required').isEmail()  
    
    var errors = req.validationErrors()
    if( !errors ) { 
        // Password hashing using bcrypt    
        var salt          = bcrypt.genSaltSync();    
        var user_password = req.sanitize('password').escape().trim();
        var passwordHash  = bcrypt.hashSync(user_password, salt);    
        
        // creating user object
        var user = {
            name       : req.sanitize('name').escape().trim(),
            email      : req.sanitize('email').escape().trim(),
            password   : passwordHash
        }
        connection.query('INSERT INTO users SET ?', user, function(err, result) {

        if (err) {
            req.flash('error', err)
            res.render('auth/register', {
                title: 'Registration Page',
                name: '',
                password: '',
                email: ''                    
            })
        } else {                
            req.flash('success', 'You have successfully signup!');
            res.redirect('/login');
        }
        });
    }
   });

```
## Risk Assessment

The impact of this flaw is high, if the attacker can gain access to an administrator account, it will be able to gain full access to the application's data. Depending on the domain of the application, this flaw could lead to the exfiltration of sensitive information, identity theft, and fraud.

## Recommendations

When implementing authentication schemas, it's highly recommended to review and follow the [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/). Section V2 Authentication Verification Requirements provides a good perspective on the elements to consider at the time of implementing such controls.

For node.js applications, it's recommended to implement and use an authentication middleware such as [passportjs](http://www.passportjs.org/) for authentication-related activities.

## References

[A2:2017-Broken Authentication](https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication)

[OWASP Application Security Verification Standard] (https://github.com/OWASP/ASVS)

