$(function () {
    function render_time() {
        return moment($(this).data('timestamp')).format('lll')
  //moment函数是由Moment.js提供，而不是flask-moment传入模板中的类
//$(this).data('timestamp')获取当前元素的data-timestamp属性值
//this当前触发事件的元素对象
    }
    $('[data-toggle="tooltip"]').tooltip(
        {title: render_time}
    );
});
//Tooltip组件需要调用tooltip()方法进行初始化。
//使用data-toggle属性作为选择器选择所有设置了tooltip的元素
//可以传入一些选项，title，可以是字符串或函数对象
