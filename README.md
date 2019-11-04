# Illumio Coding Assignment

## Testing

You can find all my unit tests in [test_firewall.py](). I also created a development csv with the test rules outlined in the assignment found in [dev.csv](). 

## Design

Because there are only 65335 ports, I decided to store port #s as indexes to lists of IP address ranges. I figured 65335 is not that large of a number, being only 16 bits of information. 

A firewall should have most of it's processing time spent in the boot-up phase, so initializing it takes a long time for many optimizations down the line. To do this, I take ranges of IP addresses and merge them together.

You will notice that I make use of python's magic methods to compare values. This is really important in building unit tests and simplifying code written down the line.

The process of events for initializing a Firewall is as follows
 * Call Firewall initialization
 * Read CSV into Address objects
 * Merge Address Objects into IP ranges by initializing an Address_rules object

The process of events for accepting a packet
 * Call method
 * Get IP ranges
 * Binary search for existence

## Future Optimizations

There is a bug where IP ranges are not merged if their boundaries are distance 1 from each other. This does not affect the output, but it can potentially cause significant slowdowns if IP addresses are inputted individually without ranges.

## Additional Comments

This was a particularly fun coding challenge, and I lost track of time while writing code for this. I went slightly over the 2 hour mark, but I'm satisfied with how I designed the code.

## Team Choice

I am interested in the teams in this order from most wanted to least
* Policy
* Data
* Platform