Active Detection with Code Cache
===================

Binário criado para detectar quando está sendo executado/analisado pelo PIN.

Requirements
-------------
> - Visual Studio 2010
> -  Pin funcional de acordo com a documentação [Intel] [1].

----------

Executing
-------------

O projeto inclui o executável já buildado.
Para testar sem o Pin, basta dar dois cliques em:
> Debug/CodeCacheDetectionByCode.exe

Para executar com o Pin:
>pin.exe -- Debug/CodeCacheDetectionByCode.exe

Os resultados possíveis para a execução do binário, são:

> * Pin Detectado:
  
  
> ![PIN_DETECTED](http://i.imgur.com/dGglmPo.png)
>
>Pelo [x32dbg](https://github.com/x64dbg) :
>
>![PIN_DETECTED](http://i.imgur.com/hMFNqfF.png)

----------     


> + Pin Não Detectado:
  
  
> ![PIN_NOT_DETECTED](http://i.imgur.com/4ISJvwW.png)
>
>Pelo [x32dbg](https://github.com/x64dbg) :
>
>![PIN_DETECTED](http://i.imgur.com/D3aFkYZ.png)


----------
Funcionamento
-------------------
O funcionamento do binário para a detecção do PIN é baseado no trabalho apresentado no Black Hat 2016 | Break Out of The Truman Show: Active Detection and Escape of Dynamic Binary Instrumentation, trabalho de Ke Sun, Xiaoning Li e Ya Ou . A apresentação está disponível neste [link](https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf).
ME

  [1]: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool
  [2]: http://daringfireball.net/projects/markdown/syntax "Markdown"
  [3]: https://github.com/jmcmanus/pagedown-extra "Pagedown Extra"
  [4]: http://meta.math.stackexchange.com/questions/5020/mathjax-basic-tutorial-and-quick-reference
  [5]: https://code.google.com/p/google-code-prettify/
  [6]: http://highlightjs.org/
  [7]: http://bramp.github.io/js-sequence-diagrams/
  [8]: http://adrai.github.io/flowchart.js/
