---
layout: default
---

# Understanding Maps (Hidden Classes) in v8

Maps store the shape of the objects and all the objects that have the same shape share the same map. For objects to have the same shape their properties should be in the same order and their types have to be the same.

<!-- Now, a question might arise in your mind. Why do we need maps? The objects (or we can say a bag of properties) are already implemented in JS. We can store and access values from an object and so on, so why have maps in v8? As we know v8 is a small cog in a huge machine called the browser and every byte and every millisecond counts. In JS if we have toa -->

The maps consists of:

* Map: the hidden class itself. It's the first pointer value in an object and therefore allows easy comparison to see if two objects have the same class.
* DescriptorArray: The full list of properties that this class has along with information about them. In some cases, the property value is even in this array.
* TransitionArray: An array of "edges" from this Map to sibling Maps. Each edge is a property name, and should be thought of as "if I were to add a property with this name to the current class, what class would I transition to?"