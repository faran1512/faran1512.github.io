---
layout: default
---

# Blog under construction (^_^)

# Understanding Maps (Hidden Classes) in v8

Maps store the shape of the objects and all the objects that have the same shape share the same map. For objects to have the same shape their properties should be in the same order and their types have to be the same.

<!-- Now, a question might arise in your mind. Why do we need maps? The objects (or we can say a bag of properties) are already implemented in JS. We can store and access values from an object and so on, so why have maps in v8? As we know v8 is a small cog in a huge machine called the browser and every byte and every millisecond counts. In JS if we have toa -->

The maps consists of:

* `Map`: the hidden class itself. It's the first pointer value in an object and therefore allows easy comparison to see if two objects have the same class.
* `DescriptorArray`: The full list of properties that this class has along with information about them. In some cases, the property value is even in this array.
* `TransitionArray`: An array of "edges" from this Map to sibling Maps. Each edge is a property name, and should be thought of as "if I were to add a property with this name to the current class, what class would I transition to?"

The purpose of maps is to save space and fast property access. Instead of objects with the same shape storing their own copies of properties and hence taking more space, Maps store the same properties at one place and only different values are stored either in-object or in properties store. The `DescriptorArray` is the one that contains the properties and their offsets that point to either their respective objects (if property is in-object) or at some in index in properties store.

Now, let's take a small example to discuss how maps are made.

```JS
var obj = {};
obj.a0 = 1;
obj.a1 = 2;
```
<p align="center">
  <img src="./Assets/Understanding_Maps_in_v8/obj_map.drawio.svg" />
</p>

The main thing to note here is that whenever a new property is added to the object, a new map is formed that contains information about the previously added properties and the new one. Now, question arises that how do the maps know where to transition next or how to go back. There is a `TransitionArray` that contains information about which map to go to if a certain property is added. Maps also contain `back_pointer` field that points to a previous map and we can go all the way back to the root map.

let's confirm our theory using d8:



```JS
var obj = {};
obj.a0 = 1;
obj.a1 = 2;